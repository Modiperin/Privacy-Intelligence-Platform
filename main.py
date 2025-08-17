from flask import Flask, request, jsonify
import os
from werkzeug.utils import secure_filename
import pdfplumber
import hashlib
import re
import easyocr
from PIL import Image
import io
import spacy

app = Flask(__name__)
reader = easyocr.Reader(['en'])
nlp = spacy.load("en_core_web_sm")

def hash_value(value: str) -> str:
    """Return a SHA256 hash for anonymization."""
    return hashlib.sha256(value.encode()).hexdigest()[:10]


PII_KEYS = [
    "Name", "Lab Id", "Client Name", "Passport No", "Sex/Age",
    "Ref. Id", "Collected at", "Collected on", "Approved on",
    "Printed On", "Location","PATIENT NAME", "SAMPLE DATE", "REF. BY DR.", "REPORT DATE", "SAMPLE COLL. AT", "SEX / AGE","Name", "Lab No.", "Age", "Ref By", "Gender"
]


key_pattern = "|".join([re.escape(k) for k in PII_KEYS])
# pattern = rf"({key_pattern})\s*:\s*([^\n:]+?)(?=\s+(?:{key_pattern})\s*:|$)"
pattern = rf"({key_pattern})\s*:\s*([^\n:]+?)(?=\s+({key_pattern})\s*:|$)"

def hash_pii_in_text(text, pii_keys):
    key_pattern = "|".join([re.escape(k) for k in pii_keys])
    # pattern = rf"({key_pattern})\s*:\s*([^\n:]+?)(?=\s+(?:{key_pattern})\s*:|$)"
    pattern = rf"({key_pattern})\s*:\s*([^\n:]+?)(?=\s+({key_pattern})\s*:|$)"
    def replacer(match):
        key, value = match.group(1), match.group(2)
        hashed = hash_value(value)
        return f"{key} : {hashed}"
    return re.sub(pattern, replacer, text, flags=re.IGNORECASE)

def mask_date_keep_month(date_str):
    """
    Masks digits in the day and year parts of a date string but preserves the month digits.
    Supports formats like '24/06/2023 08:49 PM' and variations.
    """
    pattern = re.compile(r'(\d{1,2})/(\d{1,2})/(\d{4})(.*)')
    match = pattern.match(date_str.strip())
    if match:
        day, month, year, rest = match.groups()
        masked_day = re.sub(r'\d', 'X', day)
        masked_year = re.sub(r'\d', 'X', year)
        return f"{masked_day}/{month}/{masked_year}{rest}"
    else:
        return re.sub(r'\d', 'X', date_str)


phone_pattern = re.compile(r'(\+?\d{1,3}[-.\s]?)?(\d{10})')
email_pattern = re.compile(r'\b[\w.-]+@[\w.-]+\.\w+\b')
date_time_regex = re.compile(r'\b\d{1,2}/\d{1,2}/\d{4}(\s+\d{1,2}[:.]\d{2}\s*(AM|PM)?)?\b', re.IGNORECASE)
def ner_techniques(text):
    doc = nlp(text)
    pii_spans = []

    print(doc.ents)
    for ent in doc.ents:
        if ent.label_ in ['PERSON', 'DATE','Age']:
            pii_spans.append((ent.start_char, ent.end_char))

    for m in phone_pattern.finditer(text):
        pii_spans.append((m.start(), m.end()))

    for m in email_pattern.finditer(text):
        pii_spans.append((m.start(), m.end()))
        
    for m in date_time_regex.finditer(text):
        pii_spans.append((m.start(),m.end()))

    print(pii_spans)
    pii_spans = sorted(pii_spans, key=lambda x: x[0])
    masked_text = text
    offset = 0
    for start, end in pii_spans:
        original = masked_text[start+offset:end+offset]
        if re.match(r'\d{1,2}/\d{1,2}/\d{4}', original.strip()):
            masked = mask_date_keep_month(original)
        else:
            masked = hash_value(original)
            masked_text = masked_text[:start+offset] + masked + masked_text[end+offset:]
        offset += len(masked) - (end - start)
    return masked_text


UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf"}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload-pdf", methods=["POST"])
def upload_pdf():
    try:
        sender_name = request.form.get("name")
        sender_email = request.form.get("email")

        if not sender_name or not sender_email:
            return jsonify({"error": "Name and Email are required"}), 400

        if "file" not in request.files:
            return jsonify({"error": "No file part in request"}), 400

        file = request.files["file"]

        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)
        
            with pdfplumber.open(file_path) as pdf:
                with open('file.txt','w',encoding="utf-8") as file:
                    for i, page in enumerate(pdf.pages):
                        if i >= 2:
                            break
                        text = page.extract_text_simple()
                        text = hash_pii_in_text(text, PII_KEYS)
                        print(text)
                        file.write(text + "\n")
            file.close()
            # print(text)
                

            return jsonify({
                "message": "File uploaded successfully",
                "sender": {
                    "name": sender_name,
                    "email": sender_email
                },
            }), 200
        else:
            return jsonify({"error": "Invalid file type. Only PDF allowed"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/extract-text', methods=['POST'])
def extract_text():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    img_file = request.files['image']
    img_bytes = img_file.read()
    img = Image.open(io.BytesIO(img_bytes))
    result = reader.readtext(img_bytes)

    extracted_text = " ".join([text for (_, text, _) in result])
    

    return jsonify({'extracted_text': ner_techniques(extracted_text)})

if __name__ == "__main__":
    app.run(debug=True)
