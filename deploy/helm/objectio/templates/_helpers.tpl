{{/*
Expand the name of the chart.
*/}}
{{- define "objectio.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "objectio.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "objectio.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "objectio.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.global.imageTag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "objectio.selectorLabels" -}}
app.kubernetes.io/name: {{ include "objectio.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Gateway fullname.
*/}}
{{- define "objectio.gateway.fullname" -}}
{{- printf "%s-gateway" (include "objectio.fullname" .) }}
{{- end }}

{{/*
Meta fullname.
*/}}
{{- define "objectio.meta.fullname" -}}
{{- printf "%s-meta" (include "objectio.fullname" .) }}
{{- end }}

{{/*
Meta headless service name.
*/}}
{{- define "objectio.meta.headless" -}}
{{- printf "%s-meta-headless" (include "objectio.fullname" .) }}
{{- end }}

{{/*
OSD fullname.
*/}}
{{- define "objectio.osd.fullname" -}}
{{- printf "%s-osd" (include "objectio.fullname" .) }}
{{- end }}

{{/*
OSD headless service name.
*/}}
{{- define "objectio.osd.headless" -}}
{{- printf "%s-osd-headless" (include "objectio.fullname" .) }}
{{- end }}

{{/*
Block Gateway fullname.
*/}}
{{- define "objectio.blockGateway.fullname" -}}
{{- printf "%s-block-gateway" (include "objectio.fullname" .) }}
{{- end }}

{{/*
Resolve image for a component.
If global.image is set, use it (unified all-in-one image).
Otherwise, use the per-component image from global.imageRegistry/component.image.
Usage: include "objectio.image" (dict "global" .Values.global "component" .Values.gateway)
*/}}
{{- define "objectio.image" -}}
{{- if .global.image -}}
{{- printf "%s/%s:%s" .global.imageRegistry .global.image.repository (.global.image.tag | default "latest") }}
{{- else -}}
{{- printf "%s/%s:%s" .global.imageRegistry .component.image.repository (.component.image.tag | default "latest") }}
{{- end -}}
{{- end }}

{{/*
Prometheus fullname.
*/}}
{{- define "objectio.prometheus.fullname" -}}
{{- printf "%s-prometheus" (include "objectio.fullname" .) }}
{{- end }}

{{/*
Grafana fullname.
*/}}
{{- define "objectio.grafana.fullname" -}}
{{- printf "%s-grafana" (include "objectio.fullname" .) }}
{{- end }}

{{/*
Generate comma-separated meta peer list for Raft.
Format: meta-0.HEADLESS:9100,meta-1.HEADLESS:9100,...
*/}}
{{- define "objectio.metaPeers" -}}
{{- $headless := include "objectio.meta.headless" . }}
{{- $fullname := include "objectio.meta.fullname" . }}
{{- $port := .Values.meta.service.port | int }}
{{- $peers := list }}
{{- range $i := until (.Values.meta.replicas | int) }}
{{- $peers = append $peers (printf "%s-%d.%s:%d" $fullname $i $headless $port) }}
{{- end }}
{{- join "," $peers }}
{{- end }}

{{/*
mTLS between the services (A8a): the Secret holding a role's certificate
(tls.crt, tls.key, ca.crt, as cert-manager writes them), and what each
component mounts and sets from it. Each certificate names its role in a
SAN URI, spiffe://objectio/<role>: meta, osd, gateway, block-gateway or
admin. Usage: include "objectio.tls.secretName" (dict "ctx" . "role" "meta")
*/}}
{{- define "objectio.tls.secretName" -}}
{{- (index .ctx.Values.tls.secrets .role) | default (printf "%s-tls-%s" (include "objectio.fullname" .ctx) .role) -}}
{{- end }}

{{/*
The roles there are, each with the names its certificate must carry
(the addresses peers dial it by).
*/}}
{{- define "objectio.tls.roles" -}}
{{- $roles := dict "meta" (list (include "objectio.meta.fullname" .) (include "objectio.meta.headless" .)) "osd" (list (include "objectio.osd.fullname" .) (include "objectio.osd.headless" .)) "gateway" (list (include "objectio.gateway.fullname" .)) "admin" (list) }}
{{- if .Values.blockGateway.enabled }}
{{- $_ := set $roles "block-gateway" (list (include "objectio.blockGateway.fullname" .)) }}
{{- end }}
{{- toJson $roles }}
{{- end }}

{{- define "objectio.tls.env" -}}
{{- if .Values.tls.enabled }}
- name: OBJECTIO_TLS_CERT
  value: /etc/objectio-tls/tls.crt
- name: OBJECTIO_TLS_KEY
  value: /etc/objectio-tls/tls.key
- name: OBJECTIO_TLS_CA
  value: /etc/objectio-tls/ca.crt
{{- end }}
{{- end }}

{{- define "objectio.tls.volumeMount" -}}
{{- if .Values.tls.enabled }}
- name: tls
  mountPath: /etc/objectio-tls
  readOnly: true
{{- end }}
{{- end }}

{{- /* Usage: include "objectio.tls.volume" (dict "ctx" . "role" "osd") */ -}}
{{- define "objectio.tls.volume" -}}
{{- if .ctx.Values.tls.enabled }}
- name: tls
  secret:
    secretName: {{ include "objectio.tls.secretName" . }}
{{- end }}
{{- end }}

{{/*
The tools image (sh + curl): the Raft bootstrap Job, the OSDs' node-label
lookup.
*/}}
{{- define "objectio.toolsImage" -}}
{{- printf "%s:%s" .Values.global.toolsImage.repository (.Values.global.toolsImage.tag | toString) -}}
{{- end }}

{{/*
Pod-spec fields every component takes from its values: image pull
secrets, priority class, nodeSelector, affinity, tolerations and
topologySpreadConstraints. A spread constraint without a labelSelector
gets the component's pods' labels.
Usage: include "objectio.podPlacement" (dict "root" . "values" .Values.osd "component" "osd")
*/}}
{{- define "objectio.podPlacement" -}}
{{- with .root.Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.priorityClassName }}
priorityClassName: {{ . | quote }}
{{- end }}
{{- with .values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- if .values.topologySpreadConstraints }}
{{- $labels := merge (dict "app.kubernetes.io/component" .component) (fromYaml (include "objectio.selectorLabels" .root)) }}
topologySpreadConstraints:
{{- range .values.topologySpreadConstraints }}
  - {{- toYaml (merge (deepCopy .) (dict "labelSelector" (dict "matchLabels" $labels))) | nindent 4 }}
{{- end }}
{{- end }}
{{- end }}

{{/*
The probes a component's values give (startupProbe, livenessProbe,
readinessProbe), at the container's indentation.
*/}}
{{- define "objectio.probes" -}}
{{- range $name := list "startupProbe" "livenessProbe" "readinessProbe" }}
{{- with index $.values $name }}
{{ $name }}:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Refuse values that would lose data or can't work. Rendered once, from
validate.yaml.
*/}}
{{- define "objectio.validate" -}}
{{- $k := int .Values.ec.k }}
{{- $m := int .Values.ec.m }}
{{- if lt $k 1 }}
{{- fail (printf "ec.k is %d: a stripe needs at least one data shard" $k) }}
{{- end }}
{{- $copies := int .Values.replication }}
{{- if lt $copies 0 }}
{{- fail (printf "replication is %d: 0 (erasure coding) or a number of copies" $copies) }}
{{- end }}
{{- if and (eq $copies 0) (lt $m 1) }}
{{- fail "ec.m is 0: an erasure-coded pool needs parity (one unprotected copy is replication: 1)" }}
{{- end }}
{{- if and (eq $copies 0) (lt (int .Values.osd.replicas) (add $k $m)) }}
{{- fail (printf "osd.replicas is %d, fewer than ec.k + ec.m = %d: each shard of a stripe goes to a different OSD. Add OSDs or choose a smaller code." (int .Values.osd.replicas) (add $k $m)) }}
{{- end }}
{{- if lt (int .Values.osd.replicas) $copies }}
{{- fail (printf "osd.replicas is %d, fewer than replication = %d: each copy goes to a different OSD" (int .Values.osd.replicas) $copies) }}
{{- end }}
{{- if and .Values.blockGateway.enabled (lt (int .Values.osd.replicas) (add $k $m)) }}
{{- fail (printf "the block gateway codes volumes ec.k + ec.m = %d, more than osd.replicas = %d" (add $k $m) (int .Values.osd.replicas)) }}
{{- end }}
{{- if lt (int .Values.meta.replicas) 1 }}
{{- fail "meta.replicas must be at least 1 (3 or 5 for a cluster that survives a node)" }}
{{- end }}
{{- if not (has .Values.osd.persistence.data.volumeMode (list "Filesystem" "Block")) }}
{{- fail (printf "osd.persistence.data.volumeMode is %q: Filesystem or Block" .Values.osd.persistence.data.volumeMode) }}
{{- end }}
{{- range $level, $label := .Values.osd.failureDomain.nodeLabels }}
{{- if not (has $level (list "region" "zone" "datacenter" "rack")) }}
{{- fail (printf "osd.failureDomain.nodeLabels.%s: the levels read from node labels are region, zone, datacenter and rack (host is the node itself)" $level) }}
{{- end }}
{{- if not $label }}
{{- fail (printf "osd.failureDomain.nodeLabels.%s names no label" $level) }}
{{- end }}
{{- end }}
{{- if and .Values.gateway.sse.existingSecret .Values.gateway.sse.masterKey }}
{{- fail "gateway.sse: set existingSecret or masterKey, not both" }}
{{- end }}
{{- end }}
