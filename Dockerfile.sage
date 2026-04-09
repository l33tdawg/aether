# Aether SAGE — Configured for Ollama embeddings
#
# Extends the official SAGE image with config for Ollama embedding provider.
# Ollama runs as a companion service in docker-compose.yml.

FROM ghcr.io/l33tdawg/sage:5.4.4

RUN mkdir -p /root/.sage && \
    printf 'embedding:\n  provider: ollama\n  base_url: http://ollama:11434\n  model: nomic-embed-text\n  dimension: 768\nrest_addr: "0.0.0.0:8080"\n' > /root/.sage/config.yaml

EXPOSE 8080
ENTRYPOINT ["sage-gui", "serve"]
