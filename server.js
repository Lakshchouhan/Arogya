const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));

// Root route
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/main.html');
});

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/auth_db', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.log('MongoDB Connection Error:', err));

// Disease symptoms with weights
const DISEASE_SYMPTOMS = {
    malaria: {
        primary: [
            { symptom: 'Fever', weight: 3 },
            { symptom: 'Chills', weight: 3 },
            { symptom: 'Sweating', weight: 2 }
        ],
        secondary: [
            { symptom: 'Headache', weight: 1 },
            { symptom: 'Nausea', weight: 1 },
            { symptom: 'Vomiting', weight: 1 },
            { symptom: 'Fatigue', weight: 1 },
            { symptom: 'Diarrhea', weight: 1 },
            { symptom: 'Myalgia', weight: 1 },
            { symptom: 'Splenomegaly', weight: 2 }
        ]
    },
    tuberculosis: {
        primary: [
            { symptom: 'Cough', weight: 3 },
            { symptom: 'Fever', weight: 2 },
            { symptom: 'Hemoptysis', weight: 3 }
        ],
        secondary: [
            { symptom: 'Fatigue', weight: 1 },
            { symptom: 'Weightloss', weight: 2 },
            { symptom: 'Night-sweats', weight: 2 },
            { symptom: 'Chestpain', weight: 2 },
            { symptom: 'Weakness', weight: 1 },
            { symptom: 'Anorexia', weight: 1 },
            { symptom: 'Chills', weight: 1 }
        ]
    }
};

// Disease information
const DISEASE_INFO = {
    malaria: {
        name: 'Malaria',
        precautions: [
            'Use mosquito nets while sleeping',
            'Apply mosquito repellent',
            'Wear long-sleeved clothing',
            'Take antimalarial medication as prescribed',
            'Avoid stagnant water',
            'Keep surroundings clean'
        ],
        medications: [
            'Chloroquine',
            'Artemisinin-based combination therapy (ACT)',
            'Primaquine',
            'Mefloquine',
            'Doxycycline'
        ]
    },
    tuberculosis: {
        name: 'Tuberculosis',
        precautions: [
            'Complete the full course of medication',
            'Cover mouth when coughing or sneezing',
            'Maintain good ventilation',
            'Wear a mask when in public',
            'Get regular check-ups',
            'Maintain good nutrition'
        ],
        medications: [
            'Isoniazid',
            'Rifampin',
            'Ethambutol',
            'Pyrazinamide',
            'Streptomycin'
        ]
    }
};

// Generate random medical contacts
function generateMedicalContacts() {
    const hospitals = [
        {
            name: 'City General Hospital',
            type: 'Hospital',
            phone: '+91 9876543210',
            address: '123 Medical Street, City Center'
        },
        {
            name: 'Dr. Rajesh Kumar',
            type: 'Pulmonologist',
            phone: '+91 9876543211',
            address: '456 Health Avenue, Medical District'
        },
        {
            name: 'Community Health Center',
            type: 'Clinic',
            phone: '+91 9876543212',
            address: '789 Wellness Road, Suburb'
        }
    ];
    return hospitals;
}

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profile: {
        age: { type: Number },
        sex: { type: String, enum: ['male', 'female', 'other'] },
        location: { type: String },
        profilePhoto: { type: String },
        weight: { type: Number },
        height: { type: Number },
        updatedAt: { type: Date, default: Date.now }
    },
    symptoms: [{
        description: { type: String, required: true },
        createdAt: { type: Date, default: Date.now }
    }]
});

const User = mongoose.model('User', userSchema);

// Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const user = new User({
            username,
            email,
            password: hashedPassword
        });

        await user.save();

        // Create token
        const token = jwt.sign(
            { userId: user._id },
            'your_jwt_secret', // In production, use environment variable
            { expiresIn: '1h' }
        );

        res.status(201).json({ message: 'User created successfully', token });
    } catch (error) {
        res.status(500).json({ message: 'Error creating user', error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        // Create token
        const token = jwt.sign(
            { userId: user._id },
            'your_jwt_secret', // In production, use environment variable
            { expiresIn: '1h' }
        );

        res.json({ message: 'Login successful', token });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, 'your_jwt_secret');
        req.userId = decoded.userId;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

// Get user details endpoint
app.get('/api/user', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching user details', error: error.message });
    }
});

// Update user profile endpoint
app.put('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const { age, sex, location, profilePhoto, weight, height } = req.body;
        
        // Validate required fields
        if (!age || !sex || !location || !weight || !height) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Validate age
        if (age < 1 || age > 120) {
            return res.status(400).json({ message: 'Age must be between 1 and 120' });
        }

        // Validate sex
        if (!['male', 'female', 'other'].includes(sex)) {
            return res.status(400).json({ message: 'Invalid sex value' });
        }

        // Validate weight
        if (weight < 1 || weight > 500) {
            return res.status(400).json({ message: 'Weight must be between 1 and 500 kg' });
        }

        // Validate height
        if (height < 1 || height > 300) {
            return res.status(400).json({ message: 'Height must be between 1 and 300 cm' });
        }

        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        user.profile = {
            age,
            sex,
            location,
            profilePhoto,
            weight,
            height,
            updatedAt: new Date()
        };

        await user.save();
        res.json({ 
            message: 'Profile updated successfully', 
            profile: user.profile 
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ 
            message: 'Error updating profile', 
            error: error.message 
        });
    }
});

// Update symptoms endpoint
app.post('/api/symptoms', verifyToken, async (req, res) => {
    try {
        const { description } = req.body;
        
        if (!description) {
            return res.status(400).json({ message: 'Description is required' });
        }

        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Add new symptoms to the user's symptoms array
        user.symptoms.push({
            description,
            createdAt: new Date()
        });

        await user.save();
        res.json({ 
            message: 'Symptoms recorded successfully',
            symptoms: user.symptoms[user.symptoms.length - 1]
        });
    } catch (error) {
        console.error('Symptoms recording error:', error);
        res.status(500).json({ 
            message: 'Error recording symptoms', 
            error: error.message 
        });
    }
});

// Update the AI analysis function
async function analyzeSymptomsWithAI(symptoms) {
    try {
        console.log('Starting AI analysis for symptoms:', symptoms);
        
        const prompt = `Analyze these symptoms: "${symptoms}" and provide a medical assessment in this JSON format:
        {
            "conditions": [{
                "name": "string",
                "confidence": "string",
                "severity": "HIGH/MEDIUM/LOW",
                "description": "string"
            }],
            "immediateActions": [{
                "action": "string",
                "priority": "HIGH/MEDIUM/LOW"
            }],
            "medications": [{
                "name": "string",
                "dosage": "string",
                "precautions": "string",
                "prescriptionRequired": boolean
            }],
            "lifestyleRecommendations": [{
                "recommendation": "string",
                "importance": "HIGH/MEDIUM/LOW"
            }],
            "emergencyIndicators": [{
                "indicator": "string",
                "urgency": "IMMEDIATE/SEVERE/MODERATE"
            }],
            "followUpRecommendations": [{
                "action": "string",
                "timeline": "string"
            }]
        }`;

        console.log('Sending request to OpenRouter API...');
        
        const response = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
            model: 'anthropic/claude-3-haiku:beta',  // Using a more efficient model
            messages: [
                {
                    role: 'system',
                    content: 'You are a medical analysis system. Provide concise medical assessments.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            max_tokens: 1000  // Reducing token usage
        }, {
            headers: {
                'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
                'Content-Type': 'application/json',
                'HTTP-Referer': 'http://localhost:3000',
                'X-Title': 'Medical Diagnosis System'
            }
        });

        console.log('Received response from OpenRouter API');

        // Check if response has the expected structure
        if (!response.data) {
            console.error('No data in API response');
            throw new Error('No data in API response');
        }

        if (!response.data.choices || !Array.isArray(response.data.choices)) {
            console.error('Invalid choices in API response:', response.data);
            throw new Error('Invalid choices in API response');
        }

        if (!response.data.choices[0] || !response.data.choices[0].message) {
            console.error('Invalid message in API response:', response.data.choices);
            throw new Error('Invalid message in API response');
        }

        // Parse the AI response
        const aiResponse = response.data.choices[0].message.content;
        if (!aiResponse) {
            console.error('Empty AI response');
            throw new Error('Empty AI response');
        }

        console.log('Parsing AI response...');
        let analysis;
        try {
            analysis = JSON.parse(aiResponse);
        } catch (parseError) {
            console.error('Error parsing AI response:', parseError);
            console.error('Raw AI response:', aiResponse);
            throw new Error('Invalid AI response format');
        }

        // Validate the analysis structure
        if (!analysis.conditions || !Array.isArray(analysis.conditions)) {
            console.error('Invalid analysis structure:', analysis);
            throw new Error('Invalid analysis structure: missing or invalid conditions');
        }

        console.log('AI analysis completed successfully');
        return analysis;
    } catch (error) {
        console.error('AI Analysis Error Details:');
        if (error.response) {
            console.error('API Response Status:', error.response.status);
            console.error('API Response Headers:', error.response.headers);
            console.error('API Response Data:', error.response.data);
        }
        console.error('Error Message:', error.message);
        console.error('Error Stack:', error.stack);
        throw new Error('Failed to analyze symptoms: ' + (error.response?.data?.error || error.message));
    }
}

// Update the analysis endpoint
app.get('/api/analysis', verifyToken, async (req, res) => {
    try {
        console.log('Analysis request received');
        
        const user = await User.findById(req.userId);
        if (!user) {
            console.error('User not found:', req.userId);
            return res.status(404).json({ message: 'User not found' });
        }

        // Get the latest symptoms
        const latestSymptoms = user.symptoms[user.symptoms.length - 1];
        if (!latestSymptoms) {
            console.error('No symptoms found for user:', req.userId);
            return res.status(404).json({ message: 'No symptoms found' });
        }

        console.log('Performing AI analysis for symptoms:', latestSymptoms.description);
        
        // Perform AI analysis
        const aiAnalysis = await analyzeSymptomsWithAI(latestSymptoms.description);

        // Generate random medical contacts
        const medicalContacts = generateMedicalContacts();

        console.log('Analysis completed successfully');
        
        // Return the analysis results
        res.json({
            matchedSymptoms: latestSymptoms.description,
            aiAnalysis,
            medicalContacts
        });
    } catch (error) {
        console.error('Analysis Endpoint Error:', error);
        res.status(500).json({ 
            message: 'Error analyzing symptoms',
            error: error.message
        });
    }
});

// Update PDF report generation
app.get('/api/report', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const latestSymptoms = user.symptoms[user.symptoms.length - 1];
        if (!latestSymptoms) {
            return res.status(400).json({ message: 'No symptoms recorded' });
        }

        // Get AI analysis
        const aiAnalysis = await analyzeSymptomsWithAI(latestSymptoms.description);

        if (!aiAnalysis) {
            return res.status(500).json({ message: 'Error analyzing symptoms' });
        }

        // Create PDF
        const doc = new PDFDocument();
        
        // Set response headers
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename=medical-report.pdf');
        
        // Pipe the PDF directly to the response
        doc.pipe(res);

        // Add content to PDF
        doc.fontSize(20).text('Medical Report', { align: 'center' });
        doc.moveDown();

        doc.fontSize(12).text(`Patient Name: ${user.username}`);
        doc.text(`Age: ${user.profile.age}`);
        doc.text(`Gender: ${user.profile.sex}`);
        doc.text(`Location: ${user.profile.location}`);
        doc.moveDown();

        doc.fontSize(16).text('Reported Symptoms');
        doc.fontSize(12).text(latestSymptoms.description);
        doc.moveDown();

        doc.fontSize(16).text('AI Analysis Results');
        doc.moveDown();

        // Conditions
        doc.fontSize(14).text('Potential Conditions:');
        aiAnalysis.conditions.forEach(condition => {
            doc.fontSize(12).text(`• ${condition.name} (${condition.confidence} confidence)`);
            doc.text(`  Severity: ${condition.severity}`);
            doc.text(`  Description: ${condition.description}`);
            doc.moveDown();
        });

        // Immediate Actions
        doc.fontSize(14).text('Immediate Actions:');
        aiAnalysis.immediateActions.forEach(action => {
            doc.fontSize(12).text(`• ${action.action} (Priority: ${action.priority})`);
        });
        doc.moveDown();

        // Medications
        doc.fontSize(14).text('Recommended Medications:');
        aiAnalysis.medications.forEach(med => {
            doc.fontSize(12).text(`• ${med.name}`);
            doc.text(`  Dosage: ${med.dosage}`);
            doc.text(`  Precautions: ${med.precautions}`);
            doc.text(`  Prescription Required: ${med.prescriptionRequired ? 'Yes' : 'No'}`);
            doc.moveDown();
        });

        // Lifestyle Recommendations
        doc.fontSize(14).text('Lifestyle Recommendations:');
        aiAnalysis.lifestyleRecommendations.forEach(rec => {
            doc.fontSize(12).text(`• ${rec.recommendation} (Importance: ${rec.importance})`);
        });
        doc.moveDown();

        // Emergency Indicators
        doc.fontSize(14).text('Emergency Indicators:');
        aiAnalysis.emergencyIndicators.forEach(indicator => {
            doc.fontSize(12).text(`• ${indicator.indicator} (Urgency: ${indicator.urgency})`);
        });
        doc.moveDown();

        // Follow-up Recommendations
        doc.fontSize(14).text('Follow-up Recommendations:');
        aiAnalysis.followUpRecommendations.forEach(rec => {
            doc.fontSize(12).text(`• ${rec.action} (Timeline: ${rec.timeline})`);
        });
        doc.moveDown();

        // Medical Contacts
        doc.fontSize(14).text('Medical Contacts');
        const contacts = generateMedicalContacts();
        contacts.forEach(contact => {
            doc.moveDown();
            doc.text(`${contact.name} (${contact.type})`);
            doc.text(`Phone: ${contact.phone}`);
            doc.text(`Address: ${contact.address}`);
        });

        // Finalize the PDF
        doc.end();
    } catch (error) {
        console.error('PDF generation error:', error);
        res.status(500).json({ 
            message: 'Error generating report', 
            error: error.message 
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`)); 