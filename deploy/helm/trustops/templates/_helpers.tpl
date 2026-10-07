{{/*
Expand the name of the chart.
*/}}
{{- define "trustops.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name (release-name-chart-name, truncated to DNS limits).
*/}}
{{- define "trustops.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label (chart-name-version).
*/}}
{{- define "trustops.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard label set applied to every resource.
*/}}
{{- define "trustops.labels" -}}
helm.sh/chart: {{ include "trustops.chart" . }}
{{ include "trustops.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "trustops.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trustops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Resolve the service account name.
*/}}
{{- define "trustops.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "trustops.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image reference (repository:tag, defaulting tag to appVersion).
*/}}
{{- define "trustops.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Return "true" when the runtime has its required signing secret, or an
explicit local-only insecure override. OIDC/SAML settings alone cannot boot
the authenticated server. Secret references are checked structurally here;
Kubernetes resolves their contents at deployment time.
*/}}
{{- define "trustops.authConfigured" -}}
{{- if and .Values.security.allowInsecureNoAuth (eq .Values.security.allowInsecureOverride "acknowledged") -}}
true
{{- else -}}
{{- $configured := dict -}}
{{- range .Values.env -}}
{{- $ref := get (default dict .valueFrom) "secretKeyRef" | default dict -}}
{{- if or (ne (trim (toString (default "" .value))) "") (and (get $ref "name") (get $ref "key") (not (get $ref "optional"))) -}}
{{- $_ := set $configured .name true -}}
{{- end -}}
{{- end -}}
{{- $oidc := and (hasKey $configured "TRUSTOPS_OIDC_ISSUER") (hasKey $configured "TRUSTOPS_OIDC_CLIENT_ID") (hasKey $configured "TRUSTOPS_OIDC_CLIENT_SECRET") -}}
{{- if and (hasKey $configured "TRUSTOPS_COOKIE_SIGNING_KEY") (or (not $oidc) (hasKey $configured "TRUSTOPS_SESSION_SECRET")) -}}true{{- else -}}false{{- end -}}
{{- end -}}
{{- end -}}
