import streamlit as st
import google.generativeai as genai
import os


try:
    api_key = st.secrets["GEMINI_API_KEY"]
except (FileNotFoundError, KeyError):
    print("No se ha podido obtener la api key")

if not api_key:
    st.error("No se ha encontrado la API Key de Gemini. Asegúrate de que la variable de entorno GEMINI_API_KEY o el secreto de Streamlit están configurados.")
    st.stop()

genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-2.5-flash-lite")

# ----- 🎨 Estilos de la app ----- 
st.set_page_config(page_title="Analizador de Logs de Ciberseguridad", page_icon="🛡️", layout="wide")


st.markdown(r'''
    <style>
        /* Ocultar el header de Streamlit (rectángulo blanco superior) */
        header {
            display: none !important;
        }
        .stApp {
            background-color: #1a1a2e;
            color: #e0e0e0;
        }
        /* Color de las etiquetas de los widgets */
        label {
            color: #e0e0e0 !important;
        }
        .stTextArea textarea, .stTextInput input {
            background-color: #2a2a3e;
            color: #e0e0e0;
            border-radius: 10px;
        }
        /* Cambiar el color del placeholder para que sea más visible */
        .stTextArea textarea::placeholder,
        .stTextInput input::placeholder {
            color: #e0e0e0 !important;
            opacity: 0.6; /* Hacerlo un poco más tenue que el texto escrito */
        }
        .stButton button {
            background-color: #00a8e8;
            color: white;
            border-radius: 10px;
            padding: 10px 20px;
            font-weight: bold;
            width: 100%;
        }
        .stButton button:hover {
            background-color: #007ea7;
        }
        .stJson, .stMarkdown {
            background-color: #2a2a3e;
            border: 1px solid #4f4f6a;
            padding: 15px;
            border-radius: 10px;
        }
        h1, h2, h3 {
            color: #00a8e8;
        }
    </style>
''', unsafe_allow_html=True)

# ----- 🛡️ Interfaz de la App ----- 
st.title("🛡️ Analizador Inteligente de Logs")
st.subheader("Estandarización y Triaje L1 con IA")

st.write("Introduce un log de ciberseguridad, define la etiqueta de estandarización y pulsa el botón para analizar.")

# Columnas para la entrada de datos
col1, col2 = st.columns(2)

with col1:
    log_input = st.text_area("Introduce el log aquí:", height=200, placeholder="Ej: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326")

with col2:
    tag_input = st.text_input("Etiqueta de Estandarización:", placeholder="Ej: Formato Apache Común, Syslog, JSON Firewall")

# Botón de análisis
if st.button("Estandarización y L1 Triaje"):
    if not log_input or not tag_input:
        st.warning("Por favor, introduce tanto el log como la etiqueta de estandarización.")
    else:
        with st.spinner("Procesando... La IA está analizando el log."):
            try:
                # --- PRIMERA LLAMADA A LA IA: Estandarización ---
                prompt_estandarizacion = f"""
                Eres un experto en ciberseguridad especializado en la normalización de logs.
                Tu tarea es convertir el siguiente log en un formato JSON estandarizado, basándote en la etiqueta de formato proporcionada.
                La salida debe ser únicamente el objeto JSON resultante, sin ninguna otra explicación o texto adicional.

                **Etiqueta de Formato:**
                {tag_input}

                **Log Original:**
                {log_input}
                """
                
                response_estandarizacion = model.generate_content(prompt_estandarizacion)
                log_estandarizado_json_text = response_estandarizacion.text.strip()

                # Limpiar la salida para que sea un JSON válido
                if log_estandarizado_json_text.startswith("```json"):
                    log_estandarizado_json_text = log_estandarizado_json_text[7:-3].strip()
                
                st.subheader("1. Log Estandarizado (JSON)")
                st.json(log_estandarizado_json_text)

                # --- SEGUNDA LLAMADA A LA IA: Informe Forense L1 ---
                with st.spinner("Generando informe forense L1..."):
                    prompt_informe = f"""
                    Eres un analista de ciberseguridad de Nivel 1 (L1). Has recibido un log normalizado y una alerta simulada de un SIEM.
                    Tu misión es generar un informe de triaje para un analista de Nivel 2 (L2) basándote en el framework MITRE ATT&CK.

                    **Log Normalizado:**
                    {log_estandarizado_json_text}

                    **Alerta SIEM (Simulada):**
                    "Actividad sospechosa detectada que coincide con patrones de reconocimiento."

                    **Instrucciones para el informe:**
                    1.  **Identifica la Técnica de MITRE ATT&CK:** Proporciona el ID y el nombre de la técnica más probable (ej: T1595 - Active Scanning).
                    2.  **Justificación:** Explica por qué crees que el log corresponde a esa técnica. Basa tu análisis en los datos del log.
                    3.  **Información Clave para L2:** Extrae y resalta los datos más importantes del log (IP de origen, recurso solicitado, timestamp, user-agent, etc.).
                    4.  **Recomendación de Siguiente Paso:** Sugiere una acción inmediata para el analista L2 (ej: "Verificar si la IP de origen es conocida", "Buscar actividad similar desde esta IP en otros logs").

                    Genera un informe claro y conciso en formato Markdown. Usa la fecha y día del momento actual, en formato legible.
                    """

                    response_informe = model.generate_content(prompt_informe)
                    informe_forense = response_informe.text

                    st.subheader("2. Informe de Triaje L1 (Análisis Forense)")
                    st.markdown(informe_forense)

            except Exception as e:
                st.error(f"Ha ocurrido un error durante el análisis: {e}")