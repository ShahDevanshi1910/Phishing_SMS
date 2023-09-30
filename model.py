import pickle
from keras.models import load_model
from keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing import sequence

def load_ml_model():
    # Load the Keras LSTM model
    model = load_model('phishing_model.h5')

    # Load the tokenizer
    with open('gs_clf.pkl', 'rb') as f:
        tokenizer = pickle.load(f)

    return model, tokenizer

def predict_phishing(url, model, tokenizer):
    # Preprocess the input URL
    sequences = tokenizer.texts_to_sequences([url])
    input_sequences = sequence.pad_sequences(sequences, maxlen=150)

    # Make prediction
    prediction = model.predict(input_sequences)[0][0]

    return prediction