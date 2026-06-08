{{- define "kalki-waf.name" -}}
{{- default .Chart.Name .Values.global.serviceName | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kalki-waf.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "kalki-waf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "kalki-waf.proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kalki-waf.name" . }}-proxy
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kalki-waf.api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kalki-waf.name" . }}-api
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
