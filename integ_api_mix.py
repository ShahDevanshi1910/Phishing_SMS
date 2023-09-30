from flask import Flask, request, jsonify
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import requests
import re

app = Flask(__name__)

loaded_grid_search = joblib.load('gs_clf.pkl')

# Extract the best estimator (including the TfidfVectorizer)
best_estimator = loaded_grid_search.best_estimator_

# Extract the TfidfVectorizer from the best estimator
tokenizer = best_estimator.named_steps['tfidf']

# Preprocess function using the loaded tokenizer
def preprocess_sms_text(text):
    # Tokenize the text and remove stopwords
    text_tokens = tokenizer.transform([text])
    preprocessed_text = ' '.join(text_tokens.toarray().astype(str))

    return preprocessed_text

@app.route("/receive-sms", methods=["POST"])
def receive_sms():
    try:
        # Get JSON data from the request//
        sms_data = request.get_json()
        print(sms_data)
        header = sms_data.get("header", "")
        body = sms_data.get("Body", "")
        print(header)
        print(body)
        rl_pattern = r'https?://\S+' # regex pattern for URLs
        seperate_urls = re.findall(rl_pattern, body) # extract URLs from the message body

        if not body:
            return jsonify({"error": "Empty SMS body"}), 400

        if seperate_urls != []:
            print(seperate_urls)
            result_virus= virustotal(seperate_urls[0])
            print(result_virus)

        

        # Make predictions using the loaded model
        predicted_label = best_estimator.predict([body])
        result=str(predicted_label[0])
        # print("------------------------------>"+predicted_label);

       

        return result, 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

def virustotal(url):
    payload = {"url": url}
    virus_url="https://www.virustotal.com/api/v3/urls"
    headers = {
    "accept": "application/json",
    "x-apikey": "c2ad5bb192d4f6ad664c6bf363ef5db75d76d81856d9868a0b18f8ce7196cfd5",
    "content-type": "application/x-www-form-urlencoded",
    }


    response = requests.post(virus_url, data=payload, headers=headers)

    if response.status_code == 200:
        analysis_data = response.json()

        if "data" in analysis_data:
            analysis_id = analysis_data["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            print(f"Analysis ID: {analysis_id}")

            while True:
                analysis_response = requests.get(analysis_url, headers=headers)
                analysis_result = analysis_response.json()
                analysis_status = analysis_result.get("data", {}).get("attributes", {}).get("status")

                if analysis_status == "completed":
                    verdict = analysis_result.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)

                    if verdict > 0:
                        return "The URL is malicious."
                    else:
                        return "The URL is not malicious."
                    break
                elif analysis_status == "queued" or analysis_status == "inprogress":
                    return "Analysis is still in progress. Checking again in a moment..."
                else:
                    return f"Analysis status: {analysis_status}"
                    break
        else:
            return "Unable to retrieve analysis data."
    else:
        return f"Failed to retrieve analysis results. Status code: {response.status_code}"
