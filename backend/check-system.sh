#!/bin/bash
echo "--- STARTAR LOKAL VÄKTARE ---"

# 1. Kör integrationstester med Testcontainers
./mvnw verify

# 2. Kör Gatling Performance Test
#./mvnw gatling:test

# 3. Anropa din lokala Llama (via Ollama) för att analysera resultatet
# Detta kräver att du har Ollama installerat och llama3 nedladdat
#echo "Analyserar prestanda med Llama 3..."
#curl -X POST http://localhost:11434/api/generate -d '{
#  "model": "llama3",
#  "prompt": "Analysera följande Gatling-rapport och varna för prestandaförlust: [Klistra in rapport-data här]",
#  "stream": false
#}'
