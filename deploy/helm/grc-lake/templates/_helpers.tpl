{{/*
Expand the name of the chart.
*/}}
{{- define "grc-lake.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name (release-name-chart-name, truncated to DNS limits).
*/}}
{{- define "grc-lake.fullname" -}}
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
{{- define "grc-lake.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard label set applied to every resource.
*/}}
{{- define "grc-lake.labels" -}}
helm.sh/chart: {{ include "grc-lake.chart" . }}
{{ include "grc-lake.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "grc-lake.selectorLabels" -}}
app.kubernetes.io/name: {{ include "grc-lake.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Resolve the service account name.
*/}}
{{- define "grc-lake.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "grc-lake.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image reference (repository:tag, defaulting tag to appVersion).
*/}}
{{- define "grc-lake.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Return "true" when the runtime has its required signing secret, or an
explicit local-only insecure override. OIDC/SAML settings alone cannot boot
the authenticated server. Secret references are checked structurally here;
Kubernetes resolves their contents at deployment time.
*/}}
{{- define "grc-lake.authConfigured" -}}
{{- if and .Values.security.allowInsecureNoAuth (eq .Values.security.allowInsecureOverride "acknowledged") -}}
true
{{- else -}}
{{- $configured := dict -}}
{{- range .Values.env -}}
{{- $ref := get (default dict .valueFrom) "secretKeyRef" | default dict -}}
{{- $valid := or (ne (trim (toString (default "" .value))) "") (and (get $ref "name") (get $ref "key") (not (get $ref "optional"))) -}}
{{- $_ := set $configured .name $valid -}}
{{- end -}}
{{- range .Values.env -}}
{{- if hasPrefix "TRUSTOPS_" .name -}}
{{- $canonical := printf "GRC_LAKE_%s" (trimPrefix "TRUSTOPS_" .name) -}}
{{- if not (hasKey $configured $canonical) -}}
{{- $_ := set $configured $canonical (get $configured .name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $oidc := and (get $configured "GRC_LAKE_OIDC_ISSUER") (get $configured "GRC_LAKE_OIDC_CLIENT_ID") (get $configured "GRC_LAKE_OIDC_CLIENT_SECRET") -}}
{{- if and (get $configured "GRC_LAKE_COOKIE_SIGNING_KEY") (or (not $oidc) (get $configured "GRC_LAKE_SESSION_SECRET")) -}}true{{- else -}}false{{- end -}}
{{- end -}}
{{- end -}}
