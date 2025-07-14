# Arogya – AI-Based Diagnostic System for Rural Healthcare

**Arogya** is a simple yet powerful AI-assisted web application built to improve healthcare access in rural India. It allows users to enter symptoms, receive AI-generated diagnostic suggestions using the **OpenRouter API**, and view results on a clean HTML interface. It does not use machine learning or complex databases, making it lightweight and easy to deploy.

---

## 🌟 Key Features

- 🧠 **AI Symptom Analysis** via OpenRouter API
- 🧾 **Multi-page Static Frontend** built with HTML
- 👤 **User Authentication Pages**: Login, Signup, and Profile
- 📊 **Results Display** with AI-generated suggestions
- 🔐 **Environment Config for API Key Management**

---

## 📁 Project Structure

Arogya/
├── node_modules/ # Node.js dependencies
├── public/ # Static frontend files
│ ├── dashboard.html
│ ├── login.html
│ ├── main.html
│ ├── profile.html
│ ├── results.html
│ ├── signup.html
│ ├── symptoms.html
│ └── images/ # Static images
├── .env # Environment variables (API key)
├── package.json # Project metadata
├── package-lock.json # Auto-generated lockfile
└── server.js # Main Express server


---

## 🧰 Technologies Used

- **Node.js**
- **Express.js**
- **OpenRouter API** for AI-based diagnostics
- **HTML5** for frontend interface
- **dotenv** for environment config

---

## 🚀 Setup Instructions

# 1. Clone the repository
git clone https://github.com/Lakshchouhan/Arogya.git

# 2. Move into the project directory
cd Arogya

# 3. Install required dependencies
npm install

# 4. Create the .env file and open it in Notepad
echo OPENROUTER_API_KEY=your_api_key_here > .env
notepad .env

# (Replace 'your_api_key_here' in Notepad with your actual OpenRouter API key and save)

# 5. Start the server
node server.js

Now open your browser at http://localhost:3000/main.html to access the app.


🧪 How It Works
**Users visit main.html and navigate through login/signup pages.
**On symptoms.html, they enter symptoms.
**The backend (in server.js) processes this and sends a request to the OpenRouter API.
**Results are returned and displayed via results.html.
