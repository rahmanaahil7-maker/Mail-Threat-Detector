import pandas as pd
import numpy as np
import re
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.utils.class_weight import compute_class_weight
from keras.models import Sequential
from keras.layers import Dense, Dropout, BatchNormalization
from keras.callbacks import EarlyStopping

# 1. Advanced Text Preprocessing tailored for Emails
def clean_email_text(text):
    text = str(text).lower()
    text = re.sub(r'<[^>]+>', ' ', text)  # Strip out HTML tags completely
    text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', ' httpaddr ', text) # Normalize URLs
    text = re.sub(r'\S+@\S+', ' emailaddr ', text) # Normalize email addresses
    text = re.sub(r'\d+', ' number ', text) # Normalize numbers
    text = re.sub(r'[^a-z\s]', ' ', text) # Remove all punctuation and special characters
    text = ' '.join(text.split()) # Remove extra whitespace
    return text

def train_highly_accurate_dnn():
    print("Loading dataset...")
    # Replace with your actual dataset path
    # Ensure it has columns 'text' (the email content) and 'label' (0 for safe, 1 for phishing)
    df = pd.read_csv('your_email_dataset.csv')
    
    print("Cleaning text data...")
    df['clean_text'] = df['text'].apply(clean_email_text)
    
    # 2. Contextual Vectorization (Using N-grams)
    # ngram_range=(1,2) captures phrases like "account suspended" or "click here" 
    # instead of just individual words "account" and "suspended"
    print("Vectorizing data...")
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words='english')
    X = vectorizer.fit_transform(df['clean_text']).toarray()
    y = df['label'].values
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # 3. Handle Class Imbalance
    # If you have 10,000 safe emails but only 1,000 phishing ones, the AI ignores phishing.
    # This forces the AI to pay equal attention to the minority class.
    class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
    class_weight_dict = dict(enumerate(class_weights))
    
    # 4. Optimized Model Architecture
    print("Building DNN Architecture...")
    model = Sequential()
    
    # Input layer + first hidden layer
    model.add(Dense(256, input_shape=(X_train.shape[1],), activation='relu'))
    model.add(BatchNormalization()) # Stabilizes learning
    model.add(Dropout(0.4)) # Randomly drops 40% of neurons to prevent memorization (overfitting)
    
    # Second hidden layer
    model.add(Dense(128, activation='relu'))
    model.add(BatchNormalization())
    model.add(Dropout(0.3))
    
    # Output layer (Sigmoid for binary classification: 0 to 1 probability)
    model.add(Dense(1, activation='sigmoid'))
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    
    # 5. Early Stopping
    # Stops training the moment the AI stops improving, preventing it from over-learning the training data
    early_stop = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)
    
    print("Training Model...")
    history = model.fit(
        X_train, y_train,
        validation_data=(X_test, y_test),
        epochs=20,
        batch_size=32,
        class_weight=class_weight_dict,
        callbacks=[early_stop]
    )
    
    print("Saving highly accurate model and vectorizer...")
    # Use Keras save format for the model, joblib for the vectorizer
    model.save('dnn_model.keras')
    joblib.dump(vectorizer, 'dnn_vectorizer.pkl')
    print("Complete!")

if __name__ == "__main__":
    train_highly_accurate_dnn()