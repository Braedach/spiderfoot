/**
 * Shared metadata for the Settings / Data Source Credentials pages.
 *
 * Two independent concerns live here:
 *  - Credential detection: which module/global option keys hold a
 *    third-party secret (API key, token, password), so they can be
 *    pulled out of the generic settings list and onto their own page.
 *  - Global option grouping: `GET /api/config` returns one flat dict.
 *    The backend already tags every key with a section internally
 *    (`spiderfoot/config/app_config.py` — `_KEY_TO_FIELD`), but that
 *    tagging never reaches the frontend. This mirrors it by hand so
 *    Global Settings can render as labelled groups instead of one
 *    ~130-row alphabetical list.
 */

// ── Credential detection ─────────────────────────────────────────

// Matches: *api_key*, *apikey*, *_token (end), bare "token", *_secret*,
// *secret (end), *password*, *pwd (end), *_key (end).
const CREDENTIAL_RE = /(api[_-]?key|apikey|_token$|^token$|_secret|secret$|password|pwd$|_key$)/i;

// Not data-source credentials: these two belong to the tool modules'
// remote-execution-over-SSH feature (gobuster/phoneinfoga), a different
// concept from a third-party service credential.
const CREDENTIAL_EXCLUDE = new Set(['remote_password', 'remote_ssh_key', 'remote_ssh_key_data']);

export function isCredentialOption(key: string): boolean {
  if (CREDENTIAL_EXCLUDE.has(key)) return false;
  return CREDENTIAL_RE.test(key);
}

/** Does this module have at least one credential-style option? */
export function moduleHasCredential(opts: Record<string, unknown> | undefined): boolean {
  if (!opts) return false;
  return Object.keys(opts).some(isCredentialOption);
}

// ── Global option grouping ──────────────────────────────────────

export interface GlobalKeyMeta {
  group: string;
  label: string;
  description: string;
}

interface GroupMeta {
  label: string;
  description: string;
  order: number;
}

export const GLOBAL_GROUPS: Record<string, GroupMeta> = {
  ai: { label: 'AI Provider', description: 'The LLM used for report generation and RAG analysis (Anthropic, OpenAI, Ollama, or a local/mock provider).', order: 0 },
  embedding: { label: 'Embeddings (RAG)', description: 'Model used to turn scan events into vectors for semantic correlation.', order: 1 },
  reranker: { label: 'Reranker (RAG)', description: 'Model used to re-score and filter vector search results.', order: 2 },
  vector: { label: 'Vector Search', description: 'Qdrant vector database and the vector-based correlation engine.', order: 3 },
  network: { label: 'Network & Proxy', description: 'DNS, SOCKS proxy, and outbound HTTP request behaviour.', order: 4 },
  database: { label: 'Database', description: 'PostgreSQL connection used for scan data storage.', order: 5 },
  cache_queue: { label: 'Cache & Queue', description: 'Redis-backed caching, the event bus, and background worker concurrency.', order: 6 },
  storage: { label: 'Object Storage', description: 'MinIO/S3 buckets for reports, logs, and backups.', order: 7 },
  elasticsearch: { label: 'Elasticsearch', description: 'Optional Elasticsearch export for scan events.', order: 8 },
  web_api: { label: 'Web & API', description: 'Listener host/port and logging for the web UI and REST API.', order: 9 },
  core: { label: 'Core', description: 'General scan engine behaviour.', order: 10 },
  other: { label: 'Other', description: 'Options not yet categorised.', order: 99 },
};

/**
 * Key -> (group, friendly label, description).
 * Ported by hand from `_KEY_TO_FIELD` / `FIELD_DESCRIPTIONS` in
 * spiderfoot/config/app_config.py. Any global key *not* listed here
 * still renders — just under the "Other" catch-all group, never hidden.
 */
export const GLOBAL_KEY_META: Record<string, GlobalKeyMeta> = {
  // AI provider (RAG + sf-agents report generation)
  _llm_provider: { group: 'ai', label: 'Provider', description: "LLM provider: 'anthropic', 'openai', 'ollama', 'mock', or 'huggingface'." },
  _llm_model: { group: 'ai', label: 'Model', description: "Model name, e.g. 'claude-sonnet-5-5', 'gpt-4o-mini', 'llama3'." },
  _llm_api_key: { group: 'ai', label: 'API Key', description: 'API key for the selected provider (not needed for Ollama or mock).' },
  _llm_api_base: { group: 'ai', label: 'API Base URL', description: 'Base URL for the provider API — set this for a self-hosted Ollama endpoint.' },
  _llm_temperature: { group: 'ai', label: 'Temperature', description: 'Generation temperature (0.0 = deterministic).' },
  _llm_max_tokens: { group: 'ai', label: 'Max Tokens', description: 'Maximum tokens per LLM response.' },

  // Embeddings
  _embedding_provider: { group: 'embedding', label: 'Provider', description: "'mock', 'sentence_transformer' (local), 'openai', or 'huggingface'." },
  _embedding_model: { group: 'embedding', label: 'Model', description: "Embedding model name, e.g. 'all-MiniLM-L6-v2'." },
  _embedding_dimensions: { group: 'embedding', label: 'Dimensions', description: 'Embedding vector size — must match the model output.' },
  _embedding_api_key: { group: 'embedding', label: 'API Key', description: 'API key for a remote embedding provider.' },
  _embedding_api_base: { group: 'embedding', label: 'API Base URL', description: 'Base URL for an OpenAI-compatible embedding API.' },
  _embedding_batch_size: { group: 'embedding', label: 'Batch Size', description: 'Number of texts embedded per batch.' },
  _embedding_max_tokens: { group: 'embedding', label: 'Max Tokens', description: 'Maximum token length per text for embedding.' },

  // Reranker
  _reranker_provider: { group: 'reranker', label: 'Provider', description: "'mock', 'cross_encoder' (local), 'cohere', or 'jina'." },
  _reranker_model: { group: 'reranker', label: 'Model', description: 'Cross-encoder / reranker model name.' },
  _reranker_api_key: { group: 'reranker', label: 'API Key', description: 'API key for a remote reranker provider.' },
  _reranker_top_k: { group: 'reranker', label: 'Top K', description: 'Number of top results returned after reranking.' },
  _reranker_score_threshold: { group: 'reranker', label: 'Score Threshold', description: 'Minimum score (0.0-1.0); results below this are filtered out.' },
  _reranker_accuracy: { group: 'reranker', label: 'Accuracy', description: "'low' (fast), 'medium', or 'high' (slow, more candidates)." },

  // Vector search / Qdrant / correlation
  _qdrant_enabled: { group: 'vector', label: 'Qdrant Enabled', description: 'Enable the Qdrant vector database for RAG/rerank correlations.' },
  _qdrant_backend: { group: 'vector', label: 'Qdrant Backend', description: "'memory' (dev), 'http' (production REST), or 'grpc'." },
  _qdrant_host: { group: 'vector', label: 'Qdrant Host', description: 'Qdrant server hostname.' },
  _qdrant_port: { group: 'vector', label: 'Qdrant Port', description: 'Qdrant REST API port (default 6333).' },
  _qdrant_grpc_port: { group: 'vector', label: 'Qdrant gRPC Port', description: 'Qdrant gRPC port (default 6334).' },
  _qdrant_api_key: { group: 'vector', label: 'Qdrant API Key', description: 'Qdrant API key, if authentication is enabled.' },
  _qdrant_https: { group: 'vector', label: 'Qdrant HTTPS', description: 'Use HTTPS to connect to Qdrant.' },
  _qdrant_prefix: { group: 'vector', label: 'Qdrant Collection Prefix', description: 'Collection name prefix for all SpiderFoot collections.' },
  _vector_enabled: { group: 'vector', label: 'Vector.dev Enabled', description: 'Enable the Vector.dev log/metrics pipeline.' },
  _vector_endpoint: { group: 'vector', label: 'Vector.dev Endpoint', description: 'Vector.dev pipeline endpoint.' },
  _vcorr_enabled: { group: 'vector', label: 'Vector Correlation Enabled', description: 'Enable the vector-based correlation engine.' },
  _vcorr_similarity_threshold: { group: 'vector', label: 'Same-Scan Similarity Threshold', description: 'Minimum cosine similarity (0.0-1.0) for same-scan correlations.' },
  _vcorr_cross_scan_threshold: { group: 'vector', label: 'Cross-Scan Similarity Threshold', description: 'Minimum cosine similarity (0.0-1.0) for cross-scan correlations. Higher reduces false positives.' },
  _vcorr_workspace_strategy: { group: 'vector', label: 'Workspace Strategy', description: "'federated' (query each scan independently) or 'materialized' (copy into one workspace collection)." },
  _vcorr_rerank_accuracy: { group: 'vector', label: 'Rerank Accuracy', description: "'low', 'medium', or 'high' — controls candidate pool size." },
  _vcorr_auto_index: { group: 'vector', label: 'Auto-Index on Completion', description: 'Automatically index scan events into Qdrant when a scan finishes.' },

  // Network / proxy
  _dnsserver: { group: 'network', label: 'DNS Server', description: "Override the default resolver, e.g. Google's 8.8.8.8." },
  _dnstimeout: { group: 'network', label: 'DNS Timeout', description: 'DNS lookup timeout in seconds.' },
  _fetchtimeout: { group: 'network', label: 'Fetch Timeout', description: 'Seconds before giving up on an HTTP request.' },
  _internettlds: { group: 'network', label: 'Internet TLD List URL', description: 'Source URL for the list of Internet TLDs.' },
  _internettlds_cache: { group: 'network', label: 'TLD List Cache (hours)', description: 'How long to cache the TLD list.' },
  _socks1type: { group: 'network', label: 'SOCKS Proxy Type', description: "'4', '5', 'HTTP', or 'TOR'." },
  _socks2addr: { group: 'network', label: 'SOCKS Proxy Host', description: 'SOCKS server IP address.' },
  _socks3port: { group: 'network', label: 'SOCKS Proxy Port', description: 'Usually 1080 for SOCKS4/5, 8080 for HTTP, 9050 for TOR.' },
  _socks4user: { group: 'network', label: 'SOCKS Proxy User', description: 'SOCKS4/5 username, if required.' },
  _socks5pwd: { group: 'network', label: 'SOCKS Proxy Password', description: 'SOCKS5 password, if required.' },
  _useragent: { group: 'network', label: 'User-Agent', description: "HTTP User-Agent string. Prefix with '@' to pick randomly from a file or URL." },
  _genericusers: { group: 'network', label: 'Generic Usernames', description: 'Usernames treated as generic (not attributable to one person) when found in scans.' },

  // Database
  __database: { group: 'database', label: 'Database Path (legacy)', description: 'Legacy SQLite database path, where used.' },
  _dbpath: { group: 'database', label: 'Database Path', description: 'SQLite database path, where used.' },
  _pghost: { group: 'database', label: 'Postgres Host', description: 'PostgreSQL server hostname.' },
  _pgport: { group: 'database', label: 'Postgres Port', description: 'PostgreSQL server port.' },
  _pgdb: { group: 'database', label: 'Postgres Database', description: 'PostgreSQL database name.' },
  _pguser: { group: 'database', label: 'Postgres User', description: 'PostgreSQL username.' },
  _pgpassword: { group: 'database', label: 'Postgres Password', description: 'PostgreSQL password.' },

  // Cache / queue
  _cache_backend: { group: 'cache_queue', label: 'Cache Backend', description: "Cache backend, e.g. 'redis' or 'memory'." },
  _cache_ttl: { group: 'cache_queue', label: 'Cache TTL', description: 'Default cache entry lifetime in seconds.' },
  _cache_max_size: { group: 'cache_queue', label: 'Cache Max Size', description: 'Maximum number of cached entries.' },
  _cache_redis_url: { group: 'cache_queue', label: 'Cache Redis URL', description: 'Redis connection URL used for caching.' },
  _eventbus_backend: { group: 'cache_queue', label: 'Event Bus Backend', description: "'redis', 'nats', or in-process." },
  _eventbus_redis_url: { group: 'cache_queue', label: 'Event Bus Redis URL', description: 'Redis connection URL used for the event bus.' },
  _eventbus_nats_url: { group: 'cache_queue', label: 'Event Bus NATS URL', description: 'NATS connection URL used for the event bus.' },
  _redis_url: { group: 'cache_queue', label: 'Redis URL', description: 'Primary Redis connection URL.' },
  _redis_host: { group: 'cache_queue', label: 'Redis Host', description: 'Redis server hostname.' },
  _redis_port: { group: 'cache_queue', label: 'Redis Port', description: 'Redis server port.' },
  _worker_max: { group: 'cache_queue', label: 'Max Worker Concurrency', description: 'Maximum concurrent Celery worker tasks.' },
  _worker_strategy: { group: 'cache_queue', label: 'Worker Strategy', description: 'Celery worker pool strategy.' },
  _scheduler_max_scans: { group: 'cache_queue', label: 'Max Concurrent Scans', description: 'Maximum scans the scheduler runs at once.' },
  _scheduler_poll_interval: { group: 'cache_queue', label: 'Scheduler Poll Interval', description: 'Seconds between scheduler polling passes.' },

  // Object storage
  _minio_enabled: { group: 'storage', label: 'MinIO Enabled', description: 'Enable MinIO/S3 object storage for reports, logs, and backups.' },
  _minio_endpoint: { group: 'storage', label: 'MinIO Endpoint', description: 'MinIO server endpoint (host:port, no scheme).' },
  _minio_access_key: { group: 'storage', label: 'MinIO Access Key', description: 'MinIO access key (username).' },
  _minio_secret_key: { group: 'storage', label: 'MinIO Secret Key', description: 'MinIO secret key (password).' },
  _minio_secure: { group: 'storage', label: 'MinIO Use HTTPS', description: 'Use HTTPS to connect to MinIO.' },
  _minio_region: { group: 'storage', label: 'MinIO Region', description: 'S3 region for MinIO (default us-east-1).' },
  _minio_reports_bucket: { group: 'storage', label: 'Reports Bucket', description: 'Bucket name for scan reports.' },
  _minio_logs_bucket: { group: 'storage', label: 'Logs Bucket', description: 'Bucket name for logs and event archives.' },
  _minio_pg_backups_bucket: { group: 'storage', label: 'Postgres Backups Bucket', description: 'Bucket name for PostgreSQL backups.' },
  _minio_qdrant_bucket: { group: 'storage', label: 'Qdrant Snapshots Bucket', description: 'Bucket name for Qdrant snapshots.' },
  _minio_data_bucket: { group: 'storage', label: 'Data Bucket', description: 'Bucket name for general data artefacts.' },

  // Elasticsearch
  _es_host: { group: 'elasticsearch', label: 'Host', description: 'Elasticsearch server hostname.' },
  _es_port: { group: 'elasticsearch', label: 'Port', description: 'Elasticsearch server port.' },
  _es_enabled: { group: 'elasticsearch', label: 'Enabled', description: 'Enable the Elasticsearch export.' },

  // Web / API
  _webhost: { group: 'web_api', label: 'Web UI Host', description: 'Listener host for the web UI.' },
  _webport: { group: 'web_api', label: 'Web UI Port', description: 'Listener port for the web UI.' },
  __webaddr: { group: 'web_api', label: 'Web UI Host (legacy)', description: 'Legacy listener host for the web UI.' },
  __webport: { group: 'web_api', label: 'Web UI Port (legacy)', description: 'Legacy listener port for the web UI.' },
  _apihost: { group: 'web_api', label: 'API Host', description: 'Listener host for the REST API.' },
  _apiport: { group: 'web_api', label: 'API Port', description: 'Listener port for the REST API.' },
  _apikey: { group: 'web_api', label: 'Platform API Key', description: "SpiderFoot's own REST API key — see Access Tokens for per-user keys." },
  __webaddr_apikey: { group: 'web_api', label: 'Platform API Key (legacy)', description: 'Legacy alias for the platform API key.' },
  __loglevel: { group: 'web_api', label: 'Log Level', description: 'Application log verbosity.' },
  __logfile: { group: 'web_api', label: 'Log File', description: 'Path to the application log file.' },

  // Core
  _debug: { group: 'core', label: 'Debug Mode', description: 'Enable verbose debug logging.' },
  _maxthreads: { group: 'core', label: 'Max Concurrent Modules', description: 'Maximum number of modules run concurrently per scan.' },
  __logging: { group: 'core', label: 'Logging Enabled', description: 'Enable scan event logging.' },
  __outputfilter: { group: 'core', label: 'Output Filter', description: 'Event types excluded from scan output.' },
  _production: { group: 'core', label: 'Production Mode', description: 'Run in production mode (disables debug-only behaviour).' },
};

export function metaForGlobalKey(key: string): GlobalKeyMeta {
  return GLOBAL_KEY_META[key] ?? { group: 'other', label: key, description: '' };
}
