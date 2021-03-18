package strategy

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/openshift/library-go/pkg/security/uid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kvalidation "k8s.io/apimachinery/pkg/util/validation"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/apis/policy"

	buildv1 "github.com/openshift/api/build/v1"
	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/library-go/pkg/build/naming"
	"github.com/openshift/library-go/pkg/image/reference"
	buildutil "github.com/openshift/openshift-controller-manager/pkg/build/buildutil"
)

const (
	// dockerSocketPath is the default path for the Docker socket inside the builder container
	dockerSocketPath      = "/var/run/docker.sock"
	sourceSecretMountPath = "/var/run/secrets/openshift.io/source"

	DockerPushSecretMountPath            = "/var/run/secrets/openshift.io/push"
	DockerPullSecretMountPath            = "/var/run/secrets/openshift.io/pull"
	ConfigMapBuildSourceBaseMountPath    = "/var/run/configs/openshift.io/build"
	ConfigMapBuildSystemConfigsMountPath = "/var/run/configs/openshift.io/build-system"
	ConfigMapCertsMountPath              = "/var/run/configs/openshift.io/certs"
	SecretBuildSourceBaseMountPath       = "/var/run/secrets/openshift.io/build"
	SourceImagePullSecretMountPath       = "/var/run/secrets/openshift.io/source-image"
	// ConfigMapBuildGlobalCAMountPath is the directory where cluster-wide trust bundle will be
	// mounted in the build pod
	ConfigMapBuildGlobalCAMountPath = "/var/run/configs/openshift.io/pki"

	// ExtractImageContentContainer is the name of the container that will
	// pull down input images and extract their content for input to the build.
	ExtractImageContentContainer = "extract-image-content"

	// GitCloneContainer is the name of the container that will clone the
	// build source repository and also handle binary input content.
	GitCloneContainer = "git-clone"

	// buildVolumeMountPath is where user defined BuildVolumes get mounted
	buildVolumeMountPath = "/var/run/openshift.io/volumes"
	// buildVolumeSuffix is a suffix for BuildVolume names
	buildVolumeSuffix = "user-build-volume"
)

const (
	CustomBuild = "custom-build"
	DockerBuild = "docker-build"
	StiBuild    = "sti-build"
)

var (
	// BuildControllerRefKind contains the schema.GroupVersionKind for builds.
	// This is used in the ownerRef of builder pods.
	BuildControllerRefKind = buildv1.GroupVersion.WithKind("Build")
)

// hostPortRegex matches the final "..[port]" in ConfigMap keys
var hostPortRegex = regexp.MustCompile("\\.\\.(\\d+)$")

// FatalError is an error which can't be retried.
type FatalError struct {
	// Reason the fatal error occurred
	Reason string
}

// Error implements the error interface.
func (e *FatalError) Error() string {
	return fmt.Sprintf("fatal error: %s", e.Reason)
}

// IsFatal returns true if the error is fatal
func IsFatal(err error) bool {
	_, isFatal := err.(*FatalError)
	return isFatal
}

// setupDockerSocket configures the pod to support the host's Docker socket
func setupDockerSocket(pod *corev1.Pod) {
	dockerSocketVolume := corev1.Volume{
		Name: "docker-socket",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: dockerSocketPath,
			},
		},
	}

	dockerSocketVolumeMount := corev1.VolumeMount{
		Name:      "docker-socket",
		MountPath: dockerSocketPath,
	}

	pod.Spec.Volumes = append(pod.Spec.Volumes,
		dockerSocketVolume)
	pod.Spec.Containers[0].VolumeMounts =
		append(pod.Spec.Containers[0].VolumeMounts,
			dockerSocketVolumeMount)
	for i, initContainer := range pod.Spec.InitContainers {
		if initContainer.Name == ExtractImageContentContainer {
			pod.Spec.InitContainers[i].VolumeMounts = append(pod.Spec.InitContainers[i].VolumeMounts, dockerSocketVolumeMount)
			break
		}
	}
}

// mountConfigMapVolume is a helper method responsible for actual mounting configMap
// volumes into a pod.
func mountConfigMapVolume(pod *corev1.Pod, container *corev1.Container, configMapName, mountPath, volumeSuffix string, volumeSource *corev1.VolumeSource, configMapMode int32) {
	mountVolume(pod, container, configMapName, mountPath, volumeSuffix, policy.ConfigMap, volumeSource, configMapMode)
}

// mountSecretVolume is a helper method responsible for actual mounting secret
// volumes into a pod.
func mountSecretVolume(pod *corev1.Pod, container *corev1.Container, secretName, mountPath, volumeSuffix string, volumeSource *corev1.VolumeSource, secretMode int32) {
	mountVolume(pod, container, secretName, mountPath, volumeSuffix, policy.Secret, volumeSource, secretMode)
}

// mountVolume is a helper method responsible for mounting volumes into a pod.
// The following file system types for the volume are supported:
//
// 1. ConfigMap
// 2. EmptyDir
// 3. Secret
func mountVolume(pod *corev1.Pod, container *corev1.Container, objName, mountPath, volumeSuffix string, fsType policy.FSType, volumeSource *corev1.VolumeSource, mode int32) {
	volumeName := naming.GetName(objName, volumeSuffix, kvalidation.DNS1123LabelMaxLength)

	// coerce from RFC1123 subdomain to RFC1123 label.
	volumeName = strings.Replace(volumeName, ".", "-", -1)

	volumeExists := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == volumeName {
			volumeExists = true
			break
		}
	}
	if !volumeExists {
		volume := makeVolume(volumeName, objName, mode, fsType, volumeSource)
		pod.Spec.Volumes = append(pod.Spec.Volumes, volume)
	}

	volumeMount := corev1.VolumeMount{
		Name:      volumeName,
		MountPath: mountPath,
		ReadOnly:  true,
	}
	container.VolumeMounts = append(container.VolumeMounts, volumeMount)
}

func makeVolume(volumeName, refName string, mode int32, fsType policy.FSType, volumeSource *corev1.VolumeSource) corev1.Volume {
	// TODO: Add support for key-based paths for secrets and configMaps?
	vol := corev1.Volume{
		Name:         volumeName,
		VolumeSource: corev1.VolumeSource{},
	}
	switch fsType {
	case policy.ConfigMap:
		if volumeSource != nil && volumeSource.ConfigMap != nil {
			vol.VolumeSource.ConfigMap = volumeSource.ConfigMap.DeepCopy()
		} else {
			vol.VolumeSource.ConfigMap = &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: refName,
				},
				DefaultMode: &mode,
			}
		}
	case policy.EmptyDir:
		if volumeSource != nil && volumeSource.EmptyDir != nil {
			vol.VolumeSource.EmptyDir = volumeSource.EmptyDir.DeepCopy()
		} else {
			vol.VolumeSource.EmptyDir = &corev1.EmptyDirVolumeSource{}
		}
	case policy.Secret:
		if volumeSource != nil && volumeSource.Secret != nil {
			vol.VolumeSource.Secret = volumeSource.Secret.DeepCopy()
		} else {
			vol.VolumeSource.Secret = &corev1.SecretVolumeSource{
				SecretName:  refName,
				DefaultMode: &mode,
			}
		}
	default:
		klog.V(3).Infof("File system %s is not supported for volumes. Using empty directory instead.", fsType)
		vol.VolumeSource.EmptyDir = &corev1.EmptyDirVolumeSource{}
	}

	return vol
}

// setupDockerSecrets mounts Docker Registry secrets into Pod running the build,
// allowing Docker to authenticate against private registries or Docker Hub.
func setupDockerSecrets(pod *corev1.Pod, container *corev1.Container, pushSecret, pullSecret *corev1.LocalObjectReference, imageSources []buildv1.ImageSource, secretsMode int32) {
	if pushSecret != nil {
		mountSecretVolume(pod, container, pushSecret.Name, DockerPushSecretMountPath, "push", nil, secretsMode)
		container.Env = append(container.Env, []corev1.EnvVar{
			{Name: "PUSH_DOCKERCFG_PATH", Value: DockerPushSecretMountPath},
		}...)
		klog.V(3).Infof("%s will be used for docker push in %s", DockerPushSecretMountPath, pod.Name)
	}

	if pullSecret != nil {
		mountSecretVolume(pod, container, pullSecret.Name, DockerPullSecretMountPath, "pull", nil, secretsMode)
		container.Env = append(container.Env, []corev1.EnvVar{
			{Name: "PULL_DOCKERCFG_PATH", Value: DockerPullSecretMountPath},
		}...)
		klog.V(3).Infof("%s will be used for docker pull in %s", DockerPullSecretMountPath, pod.Name)
	}

	for i, imageSource := range imageSources {
		if imageSource.PullSecret == nil {
			continue
		}
		mountPath := filepath.Join(SourceImagePullSecretMountPath, strconv.Itoa(i))
		mountSecretVolume(pod, container, imageSource.PullSecret.Name, mountPath, fmt.Sprintf("%s%d", "source-image", i), nil, secretsMode)
		container.Env = append(container.Env, []corev1.EnvVar{
			{Name: fmt.Sprintf("%s%d", "PULL_SOURCE_DOCKERCFG_PATH_", i), Value: mountPath},
		}...)
		klog.V(3).Infof("%s will be used for docker pull in %s", mountPath, pod.Name)
	}
}

// setupSourceSecrets mounts SSH key used for accessing private SCM to clone
// application source code during build.
func setupSourceSecrets(pod *corev1.Pod, container *corev1.Container, sourceSecret *corev1.LocalObjectReference, secretsMode int32) {
	if sourceSecret == nil {
		return
	}

	mountSecretVolume(pod, container, sourceSecret.Name, sourceSecretMountPath, "source", nil, secretsMode)
	klog.V(3).Infof("Installed source secrets in %s, in Pod %s/%s", sourceSecretMountPath, pod.Namespace, pod.Name)
	container.Env = append(container.Env, []corev1.EnvVar{
		{Name: "SOURCE_SECRET_PATH", Value: sourceSecretMountPath},
	}...)
}

// setupInputConfigMaps mounts the configMaps referenced by the ConfigMapBuildSource
// into a builder container.
func setupInputConfigMaps(pod *corev1.Pod, container *corev1.Container, configs []buildv1.ConfigMapBuildSource, configMapsMode int32) {
	for _, c := range configs {
		mountConfigMapVolume(pod, container, c.ConfigMap.Name, filepath.Join(ConfigMapBuildSourceBaseMountPath, c.ConfigMap.Name), "build", nil, configMapsMode)
		klog.V(3).Infof("%s will be used as a build config in %s", c.ConfigMap.Name, ConfigMapBuildSourceBaseMountPath)
	}
}

// setupInputSecrets mounts the secrets referenced by the SecretBuildSource
// into a builder container.
func setupInputSecrets(pod *corev1.Pod, container *corev1.Container, secrets []buildv1.SecretBuildSource, secretsMode int32) {
	for _, s := range secrets {
		mountSecretVolume(pod, container, s.Secret.Name, filepath.Join(SecretBuildSourceBaseMountPath, s.Secret.Name), "build", nil, secretsMode)
		klog.V(3).Infof("%s will be used as a build secret in %s", s.Secret.Name, SecretBuildSourceBaseMountPath)
	}
}

// addSourceEnvVars adds environment variables related to the source code
// repository to builder container
func addSourceEnvVars(source buildv1.BuildSource, output *[]corev1.EnvVar) {
	sourceVars := []corev1.EnvVar{}
	if source.Git != nil {
		sourceVars = append(sourceVars, corev1.EnvVar{Name: "SOURCE_REPOSITORY", Value: source.Git.URI})
		sourceVars = append(sourceVars, corev1.EnvVar{Name: "SOURCE_URI", Value: source.Git.URI})
	}
	if len(source.ContextDir) > 0 {
		sourceVars = append(sourceVars, corev1.EnvVar{Name: "SOURCE_CONTEXT_DIR", Value: source.ContextDir})
	}
	if source.Git != nil && len(source.Git.Ref) > 0 {
		sourceVars = append(sourceVars, corev1.EnvVar{Name: "SOURCE_REF", Value: source.Git.Ref})
	}
	*output = append(*output, sourceVars...)
}

// addOutputEnvVars adds env variables that provide information about the output
// target for the build
func addOutputEnvVars(buildOutput *corev1.ObjectReference, output *[]corev1.EnvVar) error {
	if buildOutput == nil {
		return nil
	}

	// output must always be a DockerImage type reference at this point.
	if buildOutput.Kind != "DockerImage" {
		return fmt.Errorf("invalid build output kind %s, must be DockerImage", buildOutput.Kind)
	}
	ref, err := reference.Parse(buildOutput.Name)
	if err != nil {
		return err
	}
	registry := ref.Registry
	ref.Registry = ""
	image := ref.String()

	outputVars := []corev1.EnvVar{
		{Name: "OUTPUT_REGISTRY", Value: registry},
		{Name: "OUTPUT_IMAGE", Value: image},
	}

	*output = append(*output, outputVars...)
	return nil
}

// addTrustedCAMountEnvVar sets the BUILD_MOUNT_ETC_PKI_CATRUST environment variable if the build
// pod needs the CA trust bundle (`/etc/pki/ca-trust`) mounted into build processes.
func addTrustedCAMountEnvVar(mountTrustedCA *bool, envVars *[]corev1.EnvVar) {
	if mountTrustedCA != nil {
		*envVars = append(*envVars, corev1.EnvVar{Name: "BUILD_MOUNT_ETC_PKI_CATRUST", Value: strconv.FormatBool(*mountTrustedCA)})
	}
}

// setupActiveDeadline sets up the Pod activeDeadlineSeconds field
func setupActiveDeadline(pod *corev1.Pod, build *buildv1.Build) *corev1.Pod {
	if build.Spec.CompletionDeadlineSeconds != nil {
		pod.Spec.ActiveDeadlineSeconds = build.Spec.CompletionDeadlineSeconds
		return pod
	}

	// RunOnceDuration admission plugin was used to include the default active deadline for run-once pods, like the build pods
	// but it was removed from OpenShift in 4.0; rather than ship the RunOnceDuration admission as webhook admission
	// plugin, which will involve creating new operator, we use a long activeDeadlineSeconds as build are
	// designed to terminate
	var defActiveDeadline int64
	defActiveDeadline = 604800 // 1 week = 60 sec * 60 min * 24 hr * 7 days
	pod.Spec.ActiveDeadlineSeconds = &defActiveDeadline
	return pod
}

// setupAdditionalSecrets creates secret volume mounts in the given pod for the given list of secrets
func setupAdditionalSecrets(pod *corev1.Pod, container *corev1.Container, secrets []buildv1.SecretSpec, secretsMode int32) {
	for _, secretSpec := range secrets {
		mountSecretVolume(pod, container, secretSpec.SecretSource.Name, secretSpec.MountPath, "secret", nil, secretsMode)
		klog.V(3).Infof("Installed additional secret in %s, in Pod %s/%s", secretSpec.MountPath, pod.Namespace, pod.Name)
	}
}

// getPodLabels creates labels for the Build Pod
func getPodLabels(build *buildv1.Build) map[string]string {
	return map[string]string{buildv1.BuildLabel: buildutil.LabelValue(build.Name)}
}

func makeOwnerReference(build *buildv1.Build) metav1.OwnerReference {
	t := true
	return metav1.OwnerReference{
		APIVersion: BuildControllerRefKind.GroupVersion().String(),
		Kind:       BuildControllerRefKind.Kind,
		Name:       build.Name,
		UID:        build.UID,
		Controller: &t,
	}
}

func setOwnerReference(pod *corev1.Pod, build *buildv1.Build) {
	pod.OwnerReferences = []metav1.OwnerReference{makeOwnerReference(build)}
}

// HasOwnerReference returns true if the build pod has an OwnerReference to the
// build.
func HasOwnerReference(pod *corev1.Pod, build *buildv1.Build) bool {
	ref := makeOwnerReference(build)

	for _, r := range pod.OwnerReferences {
		if reflect.DeepEqual(r, ref) {
			return true
		}
	}

	return false
}

// copyEnvVarSlice returns a copy of an []corev1.EnvVar
func copyEnvVarSlice(in []corev1.EnvVar) []corev1.EnvVar {
	out := make([]corev1.EnvVar, len(in))
	copy(out, in)
	return out
}

// setupContainersConfigs sets up volumes for mounting the node's configuration which governs which
// registries it knows about, whether or not they should be accessed with TLS, signature policies,
// and default bind mounts for buildah.
func setupContainersConfigs(build *buildv1.Build, pod *corev1.Pod) {
	const volumeName = "build-system-configs"
	const configDir = ConfigMapBuildSystemConfigsMountPath
	exists := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == volumeName {
			exists = true
			break
		}
	}
	if !exists {
		cmSource := &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: buildutil.GetBuildSystemConfigMapName(build),
			},
		}
		pod.Spec.Volumes = append(pod.Spec.Volumes,
			corev1.Volume{
				Name: volumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: cmSource,
				},
			},
		)
		containers := make([]corev1.Container, len(pod.Spec.Containers))
		for i, c := range pod.Spec.Containers {
			containers[i] = updateConfigsForContainer(c, volumeName, configDir)
		}
		pod.Spec.Containers = containers
		if len(pod.Spec.InitContainers) > 0 {
			initContainers := make([]corev1.Container, len(pod.Spec.InitContainers))
			for i, c := range pod.Spec.InitContainers {
				initContainers[i] = updateConfigsForContainer(c, volumeName, configDir)
			}
			pod.Spec.InitContainers = initContainers
		}
	}
}

func updateConfigsForContainer(c corev1.Container, volumeName string, configDir string) corev1.Container {
	c.VolumeMounts = append(c.VolumeMounts,
		corev1.VolumeMount{
			Name:      volumeName,
			MountPath: configDir,
			ReadOnly:  true,
		},
	)
	// registries.conf is the primary registry config file mounted in by OpenShift
	registriesConfPath := filepath.Join(configDir, buildv1.RegistryConfKey)

	// policy.json sets image policies for buildah (allowed repositories for image pull/push, etc.)
	signaturePolicyPath := filepath.Join(configDir, buildv1.SignaturePolicyKey)

	// registries.d is a directory used by buildah to support multiple registries.conf files
	// currently not created/managed by OpenShift
	registriesDirPath := filepath.Join(configDir, "registries.d")

	// storage.conf configures storage policies for buildah
	// currently not created/managed by OpenShift
	storageConfPath := filepath.Join(configDir, "storage.conf")

	// Setup environment variables for buildah
	// If these paths do not exist in the build container, buildah falls back to sane defaults.
	c.Env = append(c.Env, corev1.EnvVar{Name: "BUILD_REGISTRIES_CONF_PATH", Value: registriesConfPath})
	c.Env = append(c.Env, corev1.EnvVar{Name: "BUILD_REGISTRIES_DIR_PATH", Value: registriesDirPath})
	c.Env = append(c.Env, corev1.EnvVar{Name: "BUILD_SIGNATURE_POLICY_PATH", Value: signaturePolicyPath})
	c.Env = append(c.Env, corev1.EnvVar{Name: "BUILD_STORAGE_CONF_PATH", Value: storageConfPath})
	return c
}

// setupContainersStorage creates volumes that we'll use for holding images and working
// root filesystems for building images.
func setupContainersStorage(pod *corev1.Pod, container *corev1.Container) {
	rootExists, runExists := false, false
	for _, v := range pod.Spec.Volumes {
		if v.Name == "container-storage-root" {
			rootExists = true
		}
		if v.Name == "container-storage-run" {
			runExists = true
		}
	}
	if !rootExists {
		pod.Spec.Volumes = append(pod.Spec.Volumes,
			corev1.Volume{
				Name: "container-storage-root",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		)
	}
	if !runExists {
		pod.Spec.Volumes = append(pod.Spec.Volumes,
			corev1.Volume{
				Name: "container-storage-run",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		)
	}
	container.VolumeMounts = append(container.VolumeMounts,
		corev1.VolumeMount{
			Name:      "container-storage-root",
			MountPath: "/var/lib/containers",
		},
		corev1.VolumeMount{
			Name:      "container-storage-run",
			MountPath: "/var/run/containers",
		},
	)
}

func addVolumeMountToContainers(conts []corev1.Container, mount corev1.VolumeMount) []corev1.Container {
	containers := make([]corev1.Container, len(conts))
	for i, c := range conts {
		c.VolumeMounts = append(c.VolumeMounts, mount)
		containers[i] = c
	}
	return containers
}

// Add the namespace's ID ranges as annotations, use the downward API to make
// them appear as /etc/subuid and /etc/subgid in the build pod's containers,
// and set the RunAsUser and fsGroup to the first UID and the first GID from
// the namespace's ID ranges.
func setupBuilderUnprivilegedUser(kubeClient *clientset.Clientset, build *buildv1.Build, pod *corev1.Pod) error {
	var fsGroup *int64

	uidmap, gidmap, err := getNamespaceRanges(kubeClient, build, pod)
	if err != nil {
		return err
	}

	// Use the first UID assigned to the namespaces as our runAsUser, and
	// set the range as being available to the user in the subuid
	// annotation.
	runAsUser := int64(uidmap[0])
	subuid := fmt.Sprintf("%d:%d:%d\n", runAsUser, uidmap[0], uidmap[1])
	metav1.SetMetaDataAnnotation(&pod.ObjectMeta, "openshift.io/subuid", subuid)

	// Format the group ID ranges.
	subgid := ""
	for _, gidmapPiece := range gidmap {
		// Save the first GID in the first range, for use as the pod's fs group.
		if fsGroup == nil {
			gid := int64(gidmapPiece[0])
			fsGroup = &gid
		}
		// Set this range as also being available to the user in the subgid annotation.
		subgid = subgid + fmt.Sprintf("%d:%d:%d\n", runAsUser, gidmapPiece[0], gidmapPiece[1])
	}
	metav1.SetMetaDataAnnotation(&pod.ObjectMeta, "openshift.io/subgid", subgid)

	// Create a volume based on the annotations we just added.
	subidMode := int32(0444)
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: "idmaps",
		VolumeSource: corev1.VolumeSource{
			DownwardAPI: &corev1.DownwardAPIVolumeSource{
				Items: []corev1.DownwardAPIVolumeFile{
					{
						Path: "subuid",
						Mode: &subidMode,
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "metadata.annotations['openshift.io/subuid']",
						},
					},
					{
						Path: "subgid",
						Mode: &subidMode,
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "metadata.annotations['openshift.io/subgid']",
						},
					},
				},
			},
		},
	})

	// Mount the annotation file items into /etc in our pod's containers.
	subuidVolumeMount := corev1.VolumeMount{
		Name:      "idmaps",
		MountPath: "/etc/subuid",
		SubPath:   "subuid",
		ReadOnly:  true,
	}
	subgidVolumeMount := corev1.VolumeMount{
		Name:      "idmaps",
		MountPath: "/etc/subgid",
		SubPath:   "subgid",
		ReadOnly:  true,
	}

	// Set the fsGroup for the pod.
	if fsGroup != nil {
		if pod.Spec.SecurityContext != nil {
			pod.Spec.SecurityContext.FSGroup = fsGroup
		} else {
			pod.Spec.SecurityContext = &corev1.PodSecurityContext{
				FSGroup: fsGroup,
			}
		}
	}

	// Set the RunAsUser to the namespace's first UID for all of the containers in the pod.
	for i := range pod.Spec.InitContainers {
		pod.Spec.InitContainers[i].SecurityContext.RunAsUser = &runAsUser
		pod.Spec.InitContainers[i].VolumeMounts = append(pod.Spec.InitContainers[i].VolumeMounts, subuidVolumeMount, subgidVolumeMount)
	}
	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].SecurityContext.RunAsUser = &runAsUser
		pod.Spec.Containers[i].VolumeMounts = append(pod.Spec.Containers[i].VolumeMounts, subuidVolumeMount, subgidVolumeMount)
	}
	return nil
}

// Parse the UID and supplemental group range annotations from the client's
// namespace, and return them in the form "(UidRangeStart,UidRangeSize)" and
// "(GidRangeStart,GidRangeSize)[,...]".
func getNamespaceRanges(kubeClient *clientset.Clientset, build *buildv1.Build, pod *corev1.Pod) ([2]uint32, [][2]uint32, error) {
	var uidmap [2]uint32
	var gidmap [][2]uint32

	if kubeClient == nil || kubeClient.CoreV1() == nil {
		// if you get ranges of size=1 back, something's probably gone wrong
		return [2]uint32{0xffffffff, 1}, [][2]uint32{{0xffffffff, 1}}, nil
	}

	// Look up the ID ranges allocated for the namespace in which we're operating.
	namespace, err := kubeClient.CoreV1().Namespaces().Get(context.TODO(), build.Namespace, metav1.GetOptions{})
	if err != nil {
		return uidmap, gidmap, fmt.Errorf("failed to read configuration of namespace %s for build %s: %v", build.Namespace, build.Name, err)
	}
	// Parse a single UID block.
	if group, ok := namespace.Annotations[securityv1.UIDRangeAnnotation]; ok {
		// Parse it into a block.
		uidBlock, err := uid.ParseBlock(group)
		if err != nil {
			return uidmap, gidmap, fmt.Errorf("failed to parse UID block %q for namespace %s for build %s", group, build.Namespace, build.Name)
		}
		// Format that block into a "rangeStart:rangeSize" string.
		size := uidBlock.End - uidBlock.Start + 1
		uidmap = [2]uint32{uidBlock.Start, size}
	} else {
		return uidmap, gidmap, fmt.Errorf("failed to find UID range annotation %q for namespace %s for build %s", securityv1.UIDRangeAnnotation, build.Namespace, build.Name)
	}
	// Parse one or more GID blocks.
	if groups, ok := namespace.Annotations[securityv1.SupplementalGroupsAnnotation]; ok {
		for _, group := range strings.Split(groups, ",") {
			if group == "" {
				continue
			}
			// Parse it into a block.
			gidBlock, err := uid.ParseBlock(group)
			if err != nil {
				return uidmap, gidmap, fmt.Errorf("failed to parse GID block %q for namespace %s for build %s", group, build.Namespace, build.Name)
			}
			// Format that block into part of an ID mapping configuration that includes that block.
			size := gidBlock.End - gidBlock.Start + 1
			if len(gidmap) == 0 {
				gidmap = [][2]uint32{{gidBlock.Start, size}}
			} else {
				gidmap = append(gidmap, [2]uint32{gidBlock.Start, size})
			}
		}
	} else {
		return uidmap, gidmap, fmt.Errorf("failed to find supplemental groups annotation %q for namespace %s for build %s", securityv1.SupplementalGroupsAnnotation, build.Namespace, build.Name)
	}
	return uidmap, gidmap, nil
}

// setupBuildCAs mounts certificate authorities for the build from a predetermined ConfigMap.
func setupBuildCAs(build *buildv1.Build, pod *corev1.Pod, additionalCAs map[string]string, internalRegistryHost string) {
	casExist := false
	globalCAsExist := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == "build-ca-bundles" {
			casExist = true
		}
		if v.Name == "build-proxy-ca-bundles" {
			globalCAsExist = true
		}

		if casExist && globalCAsExist {
			break
		}
	}

	if !casExist {
		// Mount the service signing CA key for the internal registry.
		// This will be injected into the referenced ConfigMap via the openshift/service-ca-operator, and block
		// creation of the build pod until it exists.
		//
		// See https://github.com/openshift/service-serving-cert-signer
		cmSource := &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: buildutil.GetBuildCAConfigMapName(build),
			},
			Items: []corev1.KeyToPath{
				{
					Key:  buildv1.ServiceCAKey,
					Path: fmt.Sprintf("certs.d/%s/ca.crt", internalRegistryHost),
				},
			},
		}

		// Mount any additional trusted certificates via their keys.
		// Each key should be the hostname that the CA certificate applies to
		// This will be mounted to certs.d/<domain>/ca.crt so that it can be copied
		// to /etc/docker/certs.d
		for key := range additionalCAs {
			// Replace "..[port]" with ":[port]" due to limiations with ConfigMap key names
			mountDir := hostPortRegex.ReplaceAllString(key, ":$1")
			cmSource.Items = append(cmSource.Items, corev1.KeyToPath{
				Key:  key,
				Path: fmt.Sprintf("certs.d/%s/ca.crt", mountDir),
			})
		}
		pod.Spec.Volumes = append(pod.Spec.Volumes,
			corev1.Volume{
				Name: "build-ca-bundles",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: cmSource,
				},
			},
		)
		mount := corev1.VolumeMount{
			Name:      "build-ca-bundles",
			MountPath: ConfigMapCertsMountPath,
		}
		pod.Spec.Containers = addVolumeMountToContainers(pod.Spec.Containers, mount)
		pod.Spec.InitContainers = addVolumeMountToContainers(pod.Spec.InitContainers, mount)
	}

	if !globalCAsExist {
		cmSource := &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: buildutil.GetBuildGlobalCAConfigMapName(build),
			},
			//the TBD global CA injector will update the ConfigMapVolumeSource keyToPath items
			Items: []corev1.KeyToPath{
				{
					Key:  buildutil.GlobalCAConfigMapKey,
					Path: "tls-ca-bundle.pem",
				},
			},
		}

		pod.Spec.Volumes = append(pod.Spec.Volumes,
			corev1.Volume{
				Name: "build-proxy-ca-bundles",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: cmSource,
				},
			},
		)
		mount := corev1.VolumeMount{
			Name:      "build-proxy-ca-bundles",
			MountPath: ConfigMapBuildGlobalCAMountPath,
		}
		pod.Spec.Containers = addVolumeMountToContainers(pod.Spec.Containers, mount)
		pod.Spec.InitContainers = addVolumeMountToContainers(pod.Spec.InitContainers, mount)

	}
}

// setupBlobCache configures a shared volume for caching image blobs across the build pod containers.
func setupBlobCache(pod *corev1.Pod) {
	const volume = "build-blob-cache"
	const mountPath = buildutil.BuildBlobsContentCache
	exists := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == volume {
			exists = true
			break
		}
	}
	if !exists {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: volume,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
		containers := make([]corev1.Container, len(pod.Spec.Containers))
		for i, c := range pod.Spec.Containers {
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{
				Name:      volume,
				MountPath: mountPath,
			})
			c.Env = append(c.Env, corev1.EnvVar{
				Name:  "BUILD_BLOBCACHE_DIR",
				Value: mountPath,
			})
			containers[i] = c
		}
		pod.Spec.Containers = containers

		initContainers := make([]corev1.Container, len(pod.Spec.InitContainers))
		for i, ic := range pod.Spec.InitContainers {
			ic.VolumeMounts = append(ic.VolumeMounts, corev1.VolumeMount{
				Name:      volume,
				MountPath: mountPath,
			})
			ic.Env = append(ic.Env, corev1.EnvVar{
				Name:  "BUILD_BLOBCACHE_DIR",
				Value: mountPath,
			})
			initContainers[i] = ic
		}
		pod.Spec.InitContainers = initContainers
	}
}

// setupBuildVolumes sets up user defined BuildVolumes
func setupBuildVolumes(pod *corev1.Pod, buildVolumes []buildv1.BuildVolume, configMapsMode, secretsMode int32) error {
	// if there are no BuildVolumes or the pod is nil,
	// there is no processing needed, so just return quickly
	if len(buildVolumes) == 0 || pod == nil {
		return nil
	}

	usedUserVolumeMounts := make(map[string]struct{})

	// iterate over existing VolumeMounts and add to the map
	if len(pod.Spec.Containers) != 0 {
		for _, vm := range pod.Spec.Containers[0].VolumeMounts {
			usedUserVolumeMounts[vm.MountPath] = struct{}{}
		}
	}

	for _, buildVolume := range buildVolumes {
		// check for user provided mountPath collisions and return an error if one is found
		for _, bvm := range buildVolume.Mounts {
			if _, ok := usedUserVolumeMounts[bvm.DestinationPath]; ok {
				// fail if a collision is found
				return fmt.Errorf("user provided BuildVolumeMount path %q collides with VolumeMount path created by the build controller", bvm.DestinationPath)
			}
		}

		volumeSource := corev1.VolumeSource{}

		// if no collisions are found go ahead and add the volume/volume mount to the pod/container
		switch buildVolume.Source.Type {
		case buildv1.BuildVolumeSourceTypeSecret:
			volumeSource.Secret = buildVolume.Source.Secret
			mountSecretVolume(pod, &pod.Spec.Containers[0], strings.ToLower(buildVolume.Source.Secret.SecretName), PathForBuildVolume(buildVolume.Source.Secret.SecretName), buildVolumeSuffix, &volumeSource, secretsMode)
		case buildv1.BuildVolumeSourceTypeConfigMap:
			volumeSource.ConfigMap = buildVolume.Source.ConfigMap
			mountConfigMapVolume(pod, &pod.Spec.Containers[0], strings.ToLower(buildVolume.Source.ConfigMap.Name), PathForBuildVolume(buildVolume.Source.ConfigMap.Name), buildVolumeSuffix, &volumeSource, configMapsMode)
		default:
			return fmt.Errorf("encountered unsupported build volume source type %q", buildVolume.Source.Type)
		}
	}

	return nil
}

// NameForBuildVolume returns a valid pod volume name for the provided build volume name.
func NameForBuildVolume(objName string) string {
	// Volume names must be a valid DNS Label - see https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-label-names
	return naming.GetName(strings.ToLower(objName), buildVolumeSuffix, kvalidation.DNS1123LabelMaxLength)
}

// PathForBuildVolume returns the path in the builder container where the build volume is mounted.
// This should not be confused with the destination path for the volume inside buildah's runtime environment.
func PathForBuildVolume(objName string) string {
	return filepath.Join(buildVolumeMountPath, NameForBuildVolume(objName))
}
