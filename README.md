# Laboratorio de Análisis Estático de Código Fuente (SAST)
## Proyecto Web Vulnerable para Auditoría con SonarQube y SonarCloud

Este repositorio contiene una aplicación web construida con **Node.js y Express** diseñada específicamente con **11 vulnerabilidades de seguridad** y **5 bugs de código** para forzar la detección y generar métricas completas en herramientas de análisis estático (**SAST** - Static Application Security Testing) como **SonarQube** y **SonarCloud**.

---

## 📋 Matriz de Vulnerabilidades y Bugs Implementados

| # | Tipo | Vulnerabilidad / Defecto | Regla Sonar / CWE | Línea en `server.js` | Severidad Esperada |
|---|---|---|---|---|---|
| **1** | Seguridad | Credenciales y API Keys en Código Duro | CWE-798 / javascript:S2068, S6290 | L30 - L34 | **Blocker** |
| **2** | Seguridad | CORS Permisivo con Credenciales | CWE-942 / javascript:S5122 | L41 - L45 | **Critical** |
| **3** | Seguridad | Inyección SQL (SQLi) | CWE-89 / javascript:S3649, S2077 | L56 | **Blocker** |
| **4** | Seguridad | Inyección de Comandos (Command Injection / RCE) | CWE-78 / javascript:S2076, S5334 | L73 | **Blocker** |
| **5** | Seguridad | Cross-Site Scripting Reflejado (XSS) | CWE-79 / javascript:S5131, S5247 | L93 | **Major** |
| **6** | Seguridad | Salto de Directorio (Path Traversal) | CWE-22 / javascript:S2083 | L106 | **Critical** |
| **7** | Seguridad | Criptografía Rota (Uso de MD5 y SHA1) | CWE-327, CWE-328 / javascript:S2070, S4790 | L124, L127 | **Critical** |
| **8** | Seguridad | Redirección Abierta (Open Redirect) | CWE-601 / javascript:S5146 | L145 | **Major** |
| **9** | Seguridad | Server-Side Request Forgery (SSRF) | CWE-918 / javascript:S5144 | L159 | **Critical** |
| **10** | Seguridad | Token JWT Inseguro (Algoritmo 'none' y clave débil) | CWE-330 / javascript:S6730, S6731 | L175 - L179 | **Critical** |
| **11** | Seguridad | Contaminación de Prototipos (Prototype Pollution) | CWE-1321, CWE-502 / javascript:S5883 | L195 - L200 | **Major** |
| **12** | Bug | Asignación accidental dentro de `if` (`=` en vez de `===`) | javascript:S1994 | L214 | **Critical** |
| **13** | Bug | Código Inalcanzable (Dead Code después de `return`) | javascript:S1763 | L224 | **Major** |
| **14** | Bug | Ramas idénticas en estructura `if-else` | javascript:S1862 | L234 | **Major** |
| **15** | Bug | Auto-asignación inútil (`text = text`) | javascript:S1656 | L244 | **Minor** |
| **16** | Bug | Desreferencia potencial de `null / undefined` | javascript:S2259 | L251 | **Critical** |

---

## 🚀 Cómo Ejecutar la Aplicación Localmente

1. Abrir una terminal en la carpeta del proyecto:
   ```bash
   cd C:\Users\mynor\vulnerable-web-app
   ```

2. Instalar dependencias:
   ```bash
   npm install
   ```

3. Iniciar el servidor:
   ```bash
   npm start
   ```

4. Abrir en el navegador:
   ```
   http://localhost:3000
   ```

---

## ☁️ Opción 1: Escanear con SonarCloud (Recomendada, Gratuita y en la Nube)

SonarCloud no consume memoria RAM ni requiere instalar Java o Docker en tu máquina:

1. **Subir este proyecto a un repositorio en GitHub:**
   ```bash
   cd C:\Users\mynor\vulnerable-web-app
   git init
   git add .
   git commit -m "Initial commit - Vulnerable Web App for SAST"
   git branch -M main
   # Enlaza con tu repositorio público de GitHub:
   git remote add origin https://github.com/TU_USUARIO/vulnerable-web-app.git
   git push -u origin main
   ```

2. **Entrar a SonarCloud:**
   * Ve a [https://sonarcloud.io](https://sonarcloud.io).
   * Inicia sesión con tu cuenta de **GitHub**.
   * Haz clic en **"+"** ➔ **Analyze new project**.
   * Selecciona tu repositorio `vulnerable-web-app`.

3. **Ver los Resultados:**
   * En menos de 60 segundos, SonarCloud completará el análisis automático mostrando:
     * **Quality Gate:** FAILED ❌ (Rojo).
     * **Security Rating:** E (Calificación crítica).
     * **Vulnerabilities:** 10+ detectadas.
     * **Security Hotspots:** 5+ detectadas.
     * **Bugs:** 5 detectados.
     * **Code Smells:** Múltiples detectados.

---

## 🖥️ Opción 2: Escanear con SonarQube Localmente

Si tienes un servidor SonarQube local corriendo en `http://localhost:9000`:

1. Descarga el **SonarScanner CLI** para Windows desde la web oficial de SonarSource.
2. Agrega la carpeta `bin` de SonarScanner a tu variable de entorno `PATH`.
3. Desde la carpeta del proyecto ejecuta:
   ```bash
   sonar-scanner -Dsonar.host.url=http://localhost:9000 -Dsonar.login=TU_TOKEN_DE_ACCESO
   ```
4. Abre `http://localhost:9000/dashboard?id=vulnerable-web-app` para ver el reporte gráfico.
