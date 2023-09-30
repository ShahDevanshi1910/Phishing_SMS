from flask import Flask, request, jsonify
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
import requests
import re

app = Flask(__name__)

# Load the saved grid search object
loaded_grid_search = joblib.load('gs_clf.pkl')

# Extract the best estimator (including the TfidfVectorizer)
best_estimator = loaded_grid_search.best_estimator_

# Extract the TfidfVectorizer from the best estimator
tokenizer = best_estimator.named_steps['tfidf']

# Function to remove URLs from text
def remove_urls(text):
    url_pattern = r'https?://\S+|www\.\S+'
    return re.sub(url_pattern, '', text)

# Preprocess function using the loaded tokenizer
def preprocess_sms_text(text):
    # Remove URLs from the text
    text_without_urls = remove_urls(text)
    
    # Tokenize the text and remove stopwords
    text_tokens = tokenizer.transform([text_without_urls])
    
    # Convert the tokenized text to a string
    preprocessed_text = ' '.join(text_tokens[0].indices.astype(str))

    return preprocessed_text

@app.route("/receive-sms", methods=["POST"])
def receive_sms():
    try:
        # Get JSON data from the request
        sms_data = request.get_json()
        header = sms_data.get("header", "")
        body = sms_data.get("Body", "")
        print(header)
        print(body)
        # Check for URLs in the SMS body
        url_pattern = r'https?://\S+|www\.\S+'
        separate_urls = re.findall(url_pattern, body) # extract URLs from the message body
        
        print(separate_urls[0])

        if separate_urls:
            # URLs found, check if they are malicious
            url = separate_urls[0]
            result_virus = virustotal(url)
            print(result_virus)
            if result_virus == "malicious.":
                return "URL Malicious"
            else:    
                classification = classify_sms(body)

                if classification == "ham":
                    return "The message is HAM."

                return "The message is classified as spam."
                
        else:
            # If no URLs or URLs are not malicious, classify the SMS body
            classification = classify_sms(body)

            if classification == "ham":
                return "The message is HAM."

            return "The message is classified as spam."

    except Exception as e:
        return jsonify({"error": str(e)}), 500

def classify_sms(text):
    # Preprocess the text (similar to what you did before)
    preprocessed_text = preprocess_sms_text(text)

    # Use the loaded model to predict the class (ham or spam)
    prediction = loaded_grid_search.predict([preprocessed_text])

    # Return the predicted class
    return "ham" if prediction == 0 else "spam"

def virustotal(url):
    payload = {"url": url}
    virus_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": "034521d2f423341d64a6dcaf2c049dd121c80bef1144edc0a92179beab228c05",
        "content-type": "application/x-www-form-urlencoded",
    }

    response = requests.post(virus_url, data=payload, headers=headers)

    if response.status_code == 200:
        analysis_data = response.json()

        if "data" in analysis_data:
            analysis_id = analysis_data["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            while True:
                analysis_response = requests.get(analysis_url, headers=headers)
                analysis_result = analysis_response.json()
                analysis_status = analysis_result.get("data", {}).get("attributes", {}).get("status")

                if analysis_status == "completed":
                    verdict = analysis_result.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)

                    if verdict > 0:
                        return "malicious."
                    else:
                        return "Not malicious."

                elif analysis_status == "queued" or analysis_status == "inprogress":
                    return "Analysis is still in progress. Checking again in a moment..."

                else:
                    return f"Analysis status: {analysis_status}"

        else:
            return "Unable to retrieve analysis data."

    else:
        return f"Failed to retrieve analysis results. Status code: {response.status_code}"

if __name__ == "__main__":
    app.run(debug=True)