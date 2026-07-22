{{/*
Expand the name of the chart.
*/}}
{{- define "hivemind.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name.
*/}}
{{- define "hivemind.fullname" -}}
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

{{- define "hivemind.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Resolved image tag (falls back to the chart appVersion).
*/}}
{{- define "hivemind.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "hivemind.labels" -}}
helm.sh/chart: {{ include "hivemind.chart" . }}
{{ include "hivemind.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: hivemind
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels (stable across upgrades — never include version here).
*/}}
{{- define "hivemind.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hivemind.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-scoped labels. Call with (dict "ctx" . "component" "api").
*/}}
{{- define "hivemind.componentLabels" -}}
{{ include "hivemind.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "hivemind.componentSelectorLabels" -}}
{{ include "hivemind.selectorLabels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "hivemind.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "hivemind.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret holding application secrets.
*/}}
{{- define "hivemind.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "hivemind.fullname" .) }}
{{- end }}
{{- end }}

{{- define "hivemind.configMapName" -}}
{{- printf "%s-config" (include "hivemind.fullname" .) }}
{{- end }}

{{/*
ClickHouse connection helpers (bundled service or external host).
*/}}
{{- define "hivemind.clickhouse.host" -}}
{{- if .Values.clickhouse.enabled -}}
{{- printf "%s-clickhouse" (include "hivemind.fullname" .) -}}
{{- else -}}
{{- required "externalClickHouse.host is required when clickhouse.enabled=false" .Values.externalClickHouse.host -}}
{{- end -}}
{{- end }}

{{- define "hivemind.clickhouse.httpPort" -}}
{{- if .Values.clickhouse.enabled -}}{{ .Values.clickhouse.httpPort }}{{- else -}}{{ .Values.externalClickHouse.httpPort }}{{- end -}}
{{- end }}

{{- define "hivemind.clickhouse.database" -}}
{{- if .Values.clickhouse.enabled -}}{{ .Values.clickhouse.database }}{{- else -}}{{ .Values.externalClickHouse.database }}{{- end -}}
{{- end }}

{{- define "hivemind.clickhouse.user" -}}
{{- if .Values.clickhouse.enabled -}}{{ .Values.clickhouse.user }}{{- else -}}{{ .Values.externalClickHouse.user }}{{- end -}}
{{- end }}

{{/*
Redis connection helpers.
*/}}
{{- define "hivemind.redis.host" -}}
{{- if .Values.redis.enabled -}}
{{- printf "%s-redis" (include "hivemind.fullname" .) -}}
{{- else -}}
{{- required "externalRedis.host is required when redis.enabled=false" .Values.externalRedis.host -}}
{{- end -}}
{{- end }}

{{- define "hivemind.redis.port" -}}
{{- if .Values.redis.enabled -}}{{ .Values.redis.port }}{{- else -}}{{ .Values.externalRedis.port }}{{- end -}}
{{- end }}

{{/*
Whether a Redis password is in effect, and where it lives.
*/}}
{{- define "hivemind.redis.passwordSet" -}}
{{- if .Values.redis.enabled -}}{{- if .Values.redis.password }}true{{ end -}}{{- else -}}{{- if or .Values.externalRedis.password .Values.externalRedis.existingSecret }}true{{ end -}}{{- end -}}
{{- end }}

{{/*
Datastore password env entries (CLICKHOUSE_PASSWORD / REDIS_PASSWORD) sourced
from the right Secret. Included by api, worker, and migration containers.
*/}}
{{- define "hivemind.datastorePasswordEnv" -}}
{{- if .Values.clickhouse.enabled }}
{{- if .Values.clickhouse.password }}
- name: CLICKHOUSE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "hivemind.secretName" . }}
      key: CLICKHOUSE_PASSWORD
{{- end }}
{{- else }}
{{- if .Values.externalClickHouse.existingSecret }}
- name: CLICKHOUSE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.externalClickHouse.existingSecret }}
      key: {{ .Values.externalClickHouse.existingSecretKey }}
{{- else if .Values.externalClickHouse.password }}
- name: CLICKHOUSE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "hivemind.secretName" . }}
      key: CLICKHOUSE_PASSWORD
{{- end }}
{{- end }}
{{- if .Values.redis.enabled }}
{{- if .Values.redis.password }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "hivemind.secretName" . }}
      key: REDIS_PASSWORD
{{- end }}
{{- else }}
{{- if .Values.externalRedis.existingSecret }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.externalRedis.existingSecret }}
      key: {{ .Values.externalRedis.existingSecretKey }}
{{- else if .Values.externalRedis.password }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "hivemind.secretName" . }}
      key: REDIS_PASSWORD
{{- end }}
{{- end }}
{{- end }}

{{/*
envFrom for the api + worker pods: shared ConfigMap + Secret, plus user extras.
*/}}
{{- define "hivemind.envFrom" -}}
- configMapRef:
    name: {{ include "hivemind.configMapName" . }}
- secretRef:
    name: {{ include "hivemind.secretName" . }}
{{- with .Values.config.extraEnvFrom }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Resolved OTLP endpoint for tracing. Prefers an explicit override, else the
bundled collector when ClickStack is enabled.
*/}}
{{- define "hivemind.otlpEndpoint" -}}
{{- if .Values.observability.tracing.otlpEndpoint -}}
{{- .Values.observability.tracing.otlpEndpoint -}}
{{- else if and .Values.observability.collector.enabled .Values.observability.clickstack.enabled -}}
{{- printf "http://%s-otel-collector:4317" (include "hivemind.fullname" .) -}}
{{- else if .Values.observability.clickstack.enabled -}}
{{- printf "http://%s-clickstack:%v" (include "hivemind.fullname" .) .Values.observability.clickstack.otlpGrpcPort -}}
{{- end -}}
{{- end }}

{{/*
Tracing env shared by api + worker. Pass component via dict.
*/}}
{{- define "hivemind.tracingEnv" -}}
{{- $ctx := .ctx -}}
{{- $endpoint := include "hivemind.otlpEndpoint" $ctx -}}
{{- if and $ctx.Values.observability.tracing.enabled $endpoint }}
- name: TRACING_ENABLED
  value: "true"
- name: OTEL_SERVICE_NAME
  value: {{ printf "hivemind-%s" .component | quote }}
- name: OTEL_TRACES_SAMPLE_RATE
  value: {{ $ctx.Values.observability.tracing.sampleRate | quote }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ $endpoint | quote }}
{{- $headers := $ctx.Values.observability.tracing.otlpHeaders -}}
{{- if and (not $headers) $ctx.Values.observability.clickstack.enabled $ctx.Values.observability.clickstack.ingestionApiKey -}}
{{- $headers = printf "authorization=%s" $ctx.Values.observability.clickstack.ingestionApiKey -}}
{{- end -}}
{{- with $headers }}
- name: OTEL_EXPORTER_OTLP_HEADERS
  value: {{ . | quote }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Public URL the HyperDX UI is reached at — used as FRONTEND_URL so the all-in-one
anchors its post-login/auth redirects on the gateway host instead of falling back
to http://localhost:8080. Prefers an explicit override, then the Gateway hostname
(always HTTPS, TLS terminates on the listener), then the Ingress host.
*/}}
{{- define "hivemind.clickstack.externalURL" -}}
{{- $cs := .Values.observability.clickstack -}}
{{- if $cs.frontendURL -}}
{{- $cs.frontendURL -}}
{{- else if and $cs.gateway.enabled $cs.gateway.hostname -}}
{{- printf "https://%s" $cs.gateway.hostname -}}
{{- else if and $cs.ingress.enabled $cs.ingress.host -}}
{{- printf "%s://%s" (ternary "https" "http" $cs.ingress.tls.enabled) $cs.ingress.host -}}
{{- end -}}
{{- end }}

{{/*
Host parsed from externalURL — the default for both Ingress and Gateway routes.
*/}}
{{- define "hivemind.externalHost" -}}
{{- .Values.externalURL | trimPrefix "https://" | trimPrefix "http://" | trimSuffix "/" -}}
{{- end }}

{{- define "hivemind.ingressHost" -}}
{{- .Values.ingress.host | default (include "hivemind.externalHost" .) -}}
{{- end }}

{{/*
A wait-for-clickhouse init container that blocks until ClickHouse accepts a TCP
connection. A plain TCP check (not an HTTP probe) is scheme-agnostic, so it
works for the bundled HTTP node (8123) and an external TLS endpoint such as
ClickHouse Cloud (8443) alike — the app/migrations clients auto-negotiate TLS
on 443/8443 via clickhouse_connect.
*/}}
{{- define "hivemind.waitForClickHouse" -}}
- name: wait-for-clickhouse
  image: "{{ .Values.utilityImage.repository }}:{{ .Values.utilityImage.tag }}"
  imagePullPolicy: {{ .Values.utilityImage.pullPolicy }}
  {{- with .Values.securityContext }}
  securityContext:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  command:
    - sh
    - -c
    - |
      host="{{ include "hivemind.clickhouse.host" . }}"
      port="{{ include "hivemind.clickhouse.httpPort" . }}"
      echo "Waiting for ClickHouse TCP ${host}:${port} ..."
      until nc -w 3 "$host" "$port" </dev/null >/dev/null 2>&1; do
        echo "  ...not ready yet"; sleep 3;
      done
      echo "ClickHouse is reachable."
{{- end }}
