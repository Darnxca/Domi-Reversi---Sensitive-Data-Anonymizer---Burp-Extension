#!/usr/bin/env bash
#
# Build locale del jar dell'estensione SENZA Gradle (utile per il test).
# Per la submission al BApp Store si usa Gradle (`gradle shadowJar`): PortSwigger
# compila dal sorgente. Questo script fa l'equivalente minimale con javac+jar.
#
# Richiede: JDK 17+ e connessione (solo la prima volta, per scaricare le dipendenze).

set -euo pipefail
cd "$(dirname "$0")"

MONTOYA_VER="2026.7"
GSON_VER="2.14.0"
JAR="build/libs/domi-reversi-burp-1.1.0.jar"

mkdir -p lib build/libs

if [ ! -f lib/montoya-api.jar ]; then
  echo "[*] scarico montoya-api ${MONTOYA_VER}..."
  curl -sSL -o lib/montoya-api.jar \
    "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA_VER}/montoya-api-${MONTOYA_VER}.jar"
fi
if [ ! -f lib/gson.jar ]; then
  echo "[*] scarico gson ${GSON_VER}..."
  curl -sSL -o lib/gson.jar \
    "https://repo1.maven.org/maven2/com/google/code/gson/gson/${GSON_VER}/gson-${GSON_VER}.jar"
fi

echo "[*] compilo (montoya = compileOnly, gson bundlato)..."
rm -rf build/classes && mkdir -p build/classes
javac -cp "lib/montoya-api.jar:lib/gson.jar" -d build/classes \
  $(find src/main/java -name "*.java")

echo "[*] includo Gson e le risorse..."
( cd build/classes && jar xf ../../lib/gson.jar \
  && rm -rf META-INF/MANIFEST.MF META-INF/maven META-INF/*.kotlin_module module-info.class )
cp -r src/main/resources/* build/classes/

echo "[*] creo il jar..."
jar cf "${JAR}" -C build/classes .

echo "[✓] fatto -> ${JAR}"
echo "    Caricalo in Burp: Extensions > Add > Extension type: Java > seleziona il jar"
