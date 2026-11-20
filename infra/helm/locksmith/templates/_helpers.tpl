{{- define "locksmith.name" -}}
{{- default .Release.Name .Values.nameOverride | trunc 40 | trimSuffix "-" -}}
{{- end -}}

{{- define "locksmith.labels" -}}
app.kubernetes.io/name: locksmith
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "locksmith.selector" -}}
app.kubernetes.io/name: locksmith
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "locksmith.image" -}}
{{- if .img.digest -}}
{{ .img.repository }}@{{ .img.digest }}
{{- else -}}
{{ .img.repository }}:{{ default .root.Chart.AppVersion .img.tag }}
{{- end -}}
{{- end -}}

{{- define "locksmith.secretEnv" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ .secret | quote }}
      key: {{ .name }}
{{- end -}}

{{- define "locksmith.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.podSecurity.runAsUser }}
runAsGroup: {{ .Values.podSecurity.runAsGroup }}
fsGroup: {{ .Values.podSecurity.runAsGroup }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "locksmith.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: ["ALL"]
{{- end -}}

{{- define "locksmith.pullSecrets" -}}
{{- with .Values.images.pullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ . | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "locksmith.requireSecrets" -}}
{{- required "secrets.database.existingSecret is required" .Values.secrets.database.existingSecret -}}
{{- required "secrets.internal.existingSecret is required" .Values.secrets.internal.existingSecret -}}
{{- required "secrets.keyProvider.existingSecret is required" .Values.secrets.keyProvider.existingSecret -}}
{{- required "keyProvider.address is required" .Values.keyProvider.address -}}
{{- end -}}
