import streamlit as st
import pandas as pd
import hashlib
import json
from datetime import datetime
import requests
from streamlit_option_menu import option_menu
from streamlit_lottie import st_lottie
from streamlit_chat import message
import time
from pathlib import Path

import pyrebase
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Firebase configuration
firebase_config = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.getenv("FIREBASE_APP_ID"),
    "databaseURL": os.getenv("FIREBASE_DATABASE_URL")
}

# Initialize Firebase
try:
    firebase = pyrebase.initialize_app(firebase_config)
    auth = firebase.auth()
    db = firebase.database()
    
    # Test Firebase connection
    if not all([firebase_config["apiKey"], firebase_config["databaseURL"], firebase_config["authDomain"]]):
        st.error("Missing required Firebase configuration. Please check your .env file.")
        st.stop()
        
except Exception as e:
    st.error(f"Firebase initialization error: {e}")
    st.error("Please check your Firebase configuration and make sure all environment variables are set correctly.")
    st.stop()

# ---------- Page config ----------
st.set_page_config(
    page_title="TravelViz - Professional Travel Analytics",
    page_icon="✈️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Force sidebar to be always visible with CSS
st.markdown("""
<style>
/* Force sidebar to be always visible and expanded */
.css-1d391kg, .css-1lcbmhc, .css-1lcbmhc .css-1d391kg {
    width: 21rem !important;
    min-width: 21rem !important;
    max-width: 21rem !important;
}

section[data-testid="stSidebar"] {
    width: 21rem !important;
    min-width: 21rem !important;
    max-width: 21rem !important;
    transform: translateX(0) !important;
}

section[data-testid="stSidebar"] > div {
    width: 21rem !important;
    min-width: 21rem !important;
    max-width: 21rem !important;
}

/* Hide sidebar collapse button */
.css-1lcbmhc .css-1outpf7 {
    display: none !important;
}

/* Ensure main content adjusts for sidebar */
.main .block-container {
    padding-left: 1rem !important;
    max-width: calc(100% - 21rem) !important;
}

/* Additional styling for better visibility */
section[data-testid="stSidebar"] .css-ng1t4o {
    background-color: #0E1117 !important;
}
</style>
""", unsafe_allow_html=True)

# ---------- Helpers ----------
APP_DIR = Path(__file__).parent
CSS_FILE = APP_DIR / "travelviz_css.css"
AVATAR_FILE = APP_DIR / "istockphoto-2212764771-612x612.jpg"

def inject_css():
    """Inject custom CSS if file exists"""
    if CSS_FILE.exists():
        st.markdown(f"<style>{CSS_FILE.read_text()}</style>", unsafe_allow_html=True)
    else:
        # Fallback CSS
        st.markdown("""
        <style>
        .big-title {
            font-size: 2.5rem;
            font-weight: 700;
            text-align: center;
            margin-bottom: 2rem;
            color: #00D1FF;
        }
        .section-header {
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: #FF6B6B;
        }
        .metric-card {
            background: linear-gradient(135deg, #1e1e2e, #2a2a3a);
            padding: 1.5rem;
            border-radius: 15px;
            border: 1px solid #333;
            margin-bottom: 1rem;
        }
        .card-title {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #fff;
        }
        .card-subtitle {
            color: #ccc;
            font-size: 0.9rem;
        }
        .brand-head {
            text-align: center;
            margin-bottom: 2rem;
        }
        .brand {
            font-size: 1.5rem;
            font-weight: 700;
            color: #00D1FF;
        }
        .welcome {
            font-size: 0.9rem;
            color: #ccc;
        }
        .powerbi-container {
            margin: 2rem 0;
        }
        .chat-container {
            background: linear-gradient(135deg, #1e1e2e, #2a2a3a);
            padding: 2rem;
            border-radius: 15px;
            margin: 1rem 0;
        }
        .user-actions {
            margin-top: 2rem;
        }
        .profile-image-container {
            text-align: center;
            margin-bottom: 1rem;
        }
        .profile-image {
            border-radius: 50%;
            border: 3px solid #00D1FF;
            width: 160px;
            height: 160px;
            object-fit: cover;
        }
        </style>
        """, unsafe_allow_html=True)

def load_lottieurl(url: str):
    """Load Lottie animation from URL"""
    try:
        r = requests.get(url, timeout=8)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None

# ---------- Firebase Functions ----------
def create_user_firebase(email, password, full_name, username):
    """Create user in Firebase Authentication and save additional data"""
    try:
        # Validate input
        if not email or not password or len(password) < 6:
            return False, "Password must be at least 6 characters long"
        
        # Create user in Firebase Authentication
        user = auth.create_user_with_email_and_password(email, password)
        
        # Save additional user data in Realtime Database
        user_data = {
            "full_name": full_name,
            "username": username,
            "email": email,
            "theme": "dark",
            "profile_picture": "",
            "created_at": datetime.now().isoformat()
        }
        
        # Use user's UID as the key
        db.child("users").child(user['localId']).set(user_data)
        
        return True, "Account created successfully!"
        
    except Exception as e:
        error_message = str(e)
        print(f"Firebase signup error: {error_message}")  # Debug logging
        
        if "EMAIL_EXISTS" in error_message:
            return False, "Email already exists!"
        elif "WEAK_PASSWORD" in error_message:
            return False, "Password should be at least 6 characters!"
        elif "INVALID_EMAIL" in error_message:
            return False, "Invalid email format!"
        elif "TOO_MANY_ATTEMPTS_TRY_LATER" in error_message:
            return False, "Too many attempts. Please try again later."
        else:
            return False, f"Error creating account. Please try again."

def login_user_firebase(email, password):
    """Login user with Firebase Authentication"""
    try:
        # Validate input
        if not email or not password:
            return False, "Email and password are required"
        
        # Sign in user with more specific error handling
        try:
            user = auth.sign_in_with_email_and_password(email, password)
        except Exception as auth_error:
            auth_error_str = str(auth_error)
            print(f"Firebase auth error: {auth_error_str}")  # Debug logging
            
            if "INVALID_LOGIN_CREDENTIALS" in auth_error_str:
                return False, "Invalid email or password. Please check your credentials."
            elif "USER_DISABLED" in auth_error_str:
                return False, "This account has been disabled."
            elif "TOO_MANY_ATTEMPTS_TRY_LATER" in auth_error_str:
                return False, "Too many failed attempts. Please try again later."
            elif "EMAIL_NOT_FOUND" in auth_error_str:
                return False, "No account found with this email address."
            elif "INVALID_PASSWORD" in auth_error_str:
                return False, "Incorrect password."
            else:
                return False, "Login failed. Please check your credentials and try again."
        
        # Get user data from Realtime Database
        try:
            user_data = db.child("users").child(user['localId']).get()
            
            if user_data.val():
                return True, {
                    "uid": user['localId'],
                    "email": user['email'],
                    "token": user['idToken'],
                    **user_data.val()
                }
            else:
                # If user data doesn't exist in database, create basic profile
                basic_user_data = {
                    "full_name": email.split('@')[0],  # Use email username as fallback
                    "username": email.split('@')[0],
                    "email": user['email'],
                    "theme": "dark",
                    "profile_picture": "",
                    "created_at": datetime.now().isoformat()
                }
                db.child("users").child(user['localId']).set(basic_user_data)
                
                return True, {
                    "uid": user['localId'],
                    "email": user['email'],
                    "token": user['idToken'],
                    **basic_user_data
                }
                
        except Exception as db_error:
            print(f"Database error: {str(db_error)}")
            # Return basic user info even if database fails
            return True, {
                "uid": user['localId'],
                "email": user['email'],
                "token": user['idToken'],
                "full_name": email.split('@')[0],
                "username": email.split('@')[0],
                "theme": "dark",
                "profile_picture": ""
            }
            
    except Exception as e:
        error_message = str(e)
        print(f"General login error: {error_message}")  # Debug logging
        return False, "Login failed. Please try again."

def save_feedback_firebase(name, email, subject, message, rating):
    """Save feedback message to Firebase"""
    try:
        feedback_data = {
            "name": name,
            "email": email,
            "subject": subject,
            "message": message,
            "rating": rating,
            "created_at": datetime.now().isoformat(),
            "status": "new"
        }
        db.child("feedback").push(feedback_data)
        return True
    except Exception as e:
        st.error(f"Error saving feedback: {e}")
        return False

def update_user_theme_firebase(uid, theme):
    """Update user theme in Firebase"""
    try:
        db.child("users").child(uid).child("theme").set(theme)
        return True
    except Exception as e:
        st.error(f"Error updating theme: {e}")
        return False

def update_user_profile_picture_firebase(uid, profile_picture_url):
    """Update user profile picture in Firebase"""
    try:
        db.child("users").child(uid).child("profile_picture").set(profile_picture_url)
        return True
    except Exception as e:
        st.error(f"Error updating profile picture: {e}")
        return False

# ---------- Session State ----------
def init_session_state():
    """Initialize session state variables"""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "user_data" not in st.session_state:
        st.session_state.user_data = None
    if "theme" not in st.session_state:
        st.session_state.theme = "dark"
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    if "force_nav" not in st.session_state:
        st.session_state.force_nav = None

# ---------- Auth screens ----------
def login_signup_page():
    """Display login and signup page"""
    st.markdown('<h1 class="big-title">Welcome to TravelViz</h1>', unsafe_allow_html=True)

    lottie_travel = load_lottieurl("https://assets5.lottiefiles.com/packages/lf20_puciaact.json")
    if lottie_travel:
        st_lottie(lottie_travel, height=200, key="travel_animation")

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        tab1, tab2 = st.tabs(["Login", "Sign Up"])

        with tab1:
            st.markdown('<h3 class="card-title">Login to your account</h3>', unsafe_allow_html=True)
            
    
            
            with st.form("login_form"):
                email = st.text_input("Email", key="login_email", placeholder="Enter your email")
                password = st.text_input("Password", type="password", key="login_password", placeholder="Enter your password")
                login_button = st.form_submit_button("Login")
                
                if login_button:
                    if email and password:
                        # Basic email validation
                        if "@" not in email or "." not in email:
                            st.error("Please enter a valid email address")
                        else:
                            with st.spinner("Logging in..."):
                                success, result = login_user_firebase(email.strip(), password)
                                
                            if success:
                                st.session_state.authenticated = True
                                st.session_state.user_data = result
                                st.session_state.theme = result.get("theme", "dark")
                                st.success("Login successful!")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error(result)
                    else:
                        st.warning("Please fill all fields!")
            
            # Add test account info
            st.info("💡 **Testing?** Create a new account first, then use those credentials to log in.")

        with tab2:
            st.markdown('<h3 class="card-title">Create new account</h3>', unsafe_allow_html=True)
            
            with st.form("signup_form"):
                full_name = st.text_input("Full Name", key="signup_name", placeholder="Enter your full name")
                username = st.text_input("Username", key="signup_username", placeholder="Choose a username")
                email = st.text_input("Email", key="signup_email", placeholder="Enter your email")
                password = st.text_input("Password", type="password", key="signup_password", 
                                       placeholder="Password (min 6 characters)")
                confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password",
                                               placeholder="Confirm your password")
                signup_button = st.form_submit_button("Sign Up")
                
                if signup_button:
                    if all([full_name, username, email, password, confirm_password]):
                        # Basic email validation
                        if "@" not in email or "." not in email:
                            st.error("Please enter a valid email address")
                        elif len(password) < 6:
                            st.error("Password must be at least 6 characters long")
                        elif password != confirm_password:
                            st.error("Passwords don't match!")
                        else:
                            with st.spinner("Creating account..."):
                                success, message = create_user_firebase(email.strip(), password, full_name, username)
                            
                            if success:
                                st.success(message + " Please login with your credentials.")
                                # Clear the form
                                time.sleep(2)
                                st.rerun()
                            else:
                                st.error(message)
                    else:
                        st.warning("Please fill all fields!")
            
            st.info("🔒 Your data is securely stored with Firebase Authentication")

# ---------- Pages ----------
def home_page():
    """Home page content"""
    st.markdown('<h1 class="big-title">TravelViz Analytics Platform</h1>', unsafe_allow_html=True)
    
    lottie_analytics = load_lottieurl("https://assets2.lottiefiles.com/packages/lf20_qp1q7mct.json")
    if lottie_analytics:
        st_lottie(lottie_analytics, height=300, key="analytics_animation")

    c1, c2, c3 = st.columns(3)
    features = [
        ("Advanced Analytics", "Comprehensive travel data visualization with Power BI integration"),
        ("🤖 AI Insights", "Get intelligent travel recommendations powered by AI"),
        ("📱 Responsive Design", "Modern, mobile-friendly interface with dark theme"),
    ]
    
    for col, (title, subtitle) in zip([c1, c2, c3], features):
        with col:
            st.markdown(
                f"""
                <div class="metric-card">
                    <h5 class="card-title">{title}</h5>
                    <p class="card-subtitle">{subtitle}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    user_name = st.session_state.user_data.get('full_name', 'User')
    st.markdown(
        f"""
        <div class="metric-card">
            <h3 class="card-title">Welcome, {user_name}!</h3>
            <p class="card-subtitle">Explore your travel analytics dashboard and get AI-powered insights for your next adventure.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

def dashboard_page():
    """Dashboard page with Power BI embed"""
    st.markdown('<h2 class="section-header">Travel Analytics Dashboard</h2>', unsafe_allow_html=True)

    left, right = st.columns([3, 1])
    with right:
        if st.button("🔗 Open in New Tab"):
            st.markdown(
                """
                <script>
                    window.open('https://app.powerbi.com/groups/me/reports/dc95eebc-ae53-4eac-8f38-5c51243721bf/5fcef08e14829b27d5f2?experience=power-bi');
                </script>
                """,
                unsafe_allow_html=True,
            )

    st.markdown(
        """
        <div class="powerbi-container">
            <iframe 
                title="Aptpath" 
                width="100%" 
                height="600" 
                src="https://app.powerbi.com/reportEmbed?reportId=dc95eebc-ae53-4eac-8f38-5c51243721bf&autoAuth=true&ctid=872c485a-f038-44f3-9af0-e5948115462d" 
                frameborder="0" 
                allowFullScreen="true"
                style="border-radius: 15px;">
            </iframe>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Statistics cards
    a, b, c, d = st.columns(4)
    stats = [
        ("Total countries", "153", "#FF6B6B"),
        ("Total years", "10", "#00D1FF"),
        ("Min Arrivals", "3400", "#FF6B6B"),
        ("Growth %", "48.5%", "#00D1FF"),
    ]
    
    for col, (title, val, color) in zip([a, b, c, d], stats):
        with col:
            st.markdown(
                f"""
                <div class="metric-card">
                    <h6 class="card-title">{title}</h6>
                    <h5 style="color: {color}; margin: 0;">{val}</h5>
                </div>
                """,
                unsafe_allow_html=True,
            )

def insights_page():
    """AI insights page with Q&A dataset chatbot functionality"""
    st.markdown('<h2 class="section-header">AI Travel Insights</h2>', unsafe_allow_html=True)
    st.info("🤖 Ask me anything about your TravelViz dashboard data - I can answer questions based on the Power BI analytics!")

    # Q&A Dataset
    qa_dataset = [
        ("Which country had the highest tourist arrivals overall?", "The United States, with 546M arrivals."),
        ("Which country had the second highest arrivals?", "Spain, with 552M arrivals."),
        ("What is the growth percentage for Vanuatu?", "0.12%."),
        ("How many total tourist arrivals were recorded from 2003 to 2012?", "8263M total tourist arrivals."),
        ("What was the growth percentage across all countries?", "48.54%."),
        ("How many countries are covered in the dashboard?", "153 countries."),
        ("How many years are covered in the data?", "10 years, from 2003 to 2012."),
        ("Which year had the highest arrivals?", "2012, with 82M arrivals."),
        ("Which year had the lowest arrivals?", "2003, with 49M arrivals."),
        ("What is the forecasted number of arrivals for the next year?", "Around 1 billion arrivals (based on the forecast chart)."),
        ("Which countries are in the top 10 for total arrivals?", "United States, Vietnam, Zimbabwe, Uruguay, Yemen Rep., Zambia, Venezuela RB, Virgin Islands (U.S.), West Bank & Gaza, Vanuatu."),
        ("What is the average number of arrivals per country?", "5.40M average arrivals."),
        ("What is the maximum number of arrivals for a country?", "83M."),
        ("What is the minimum number of arrivals for a country?", "3400."),
        ("Which country had the largest % change in tourism arrivals?", "Vanuatu with 669% change.")
    ]

    def find_best_answer(user_input):
        """Find the best matching answer from Q&A dataset using fuzzy matching"""
        import difflib
        
        user_input_lower = user_input.lower()
        best_match = None
        best_score = 0
        
        for question, answer in qa_dataset:
            # Check for direct keyword matches first
            question_lower = question.lower()
            
            # Calculate similarity using difflib
            similarity = difflib.SequenceMatcher(None, user_input_lower, question_lower).ratio()
            
            # Boost score for keyword matches
            keywords_in_question = question_lower.split()
            keywords_in_user = user_input_lower.split()
            keyword_matches = sum(1 for word in keywords_in_user if any(word in q_word for q_word in keywords_in_question))
            
            # Combined score
            final_score = similarity + (keyword_matches * 0.1)
            
            if final_score > best_score and final_score > 0.3:  # Minimum threshold
                best_score = final_score
                best_match = (question, answer)
        
        if best_match:
            return best_match[1]
        else:
            return "I can only answer questions based on the dashboard data. Please ask about tourist arrivals, countries, years (2003-2012), growth percentages, or forecasts."

    st.markdown('<div class="chat-container">', unsafe_allow_html=True)
    st.markdown('<h3 class="card-title">Dashboard Q&A Assistant</h3>', unsafe_allow_html=True)
    st.markdown('<p class="card-subtitle">Ask questions about tourist arrivals, countries, growth rates, and forecasts from the Power BI dashboard (2003-2012 data)</p>', unsafe_allow_html=True)

    # Display chat history
    for i, msg in enumerate(st.session_state.chat_history):
        if msg['role'] == 'user':
            message(msg['content'], is_user=True, key=f"user_{i}")
        else:
            message(msg['content'], key=f"bot_{i}")

    # Quick question buttons based on Q&A dataset
    st.markdown("**🎯 Quick Questions:**")
    
    col1, col2, col3 = st.columns(3)
    quick_questions = [
        ("🏆 Highest Arrivals", "Which country had the highest tourist arrivals overall?"),
        ("📊 Total Countries", "How many countries are covered in the dashboard?"),
        ("📈 Growth Rate", "What was the growth percentage across all countries?")
    ]
    
    for col, (button_text, question) in zip([col1, col2, col3], quick_questions):
        if col.button(button_text):
            answer = find_best_answer(question)
            st.session_state.chat_history.extend([
                {'role': 'user', 'content': question},
                {'role': 'assistant', 'content': answer}
            ])
            st.rerun()



    

    # Chat input
    user_input = st.text_input("Ask about dashboard data (countries, arrivals, years 2003-2012, growth rates, forecasts)...", key="chat_input")
    
    col_send, col_clear = st.columns([1, 1])
    with col_send:
        if st.button("📊 Ask", key="send_btn") and user_input:
            st.session_state.chat_history.append({'role': 'user', 'content': user_input})
            with st.spinner("Searching dashboard data..."):
                time.sleep(0.8)  # Brief delay for UX
                response = find_best_answer(user_input)
                st.session_state.chat_history.append({'role': 'assistant', 'content': response})
            st.rerun()
    
    with col_clear:
        if st.button("🗑️ Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()

    

def profile_page():
    """Enhanced profile page with profile picture upload functionality"""
    st.markdown('<h2 class="section-header">User Profile</h2>', unsafe_allow_html=True)

    user = st.session_state.user_data
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.markdown('<div class="profile-image-container">', unsafe_allow_html=True)
        
        # Display current profile picture
        profile_picture = user.get('profile_picture', '')
        if profile_picture:
            st.markdown(f'<img src="data:image/jpeg;base64,{profile_picture}" class="profile-image">', unsafe_allow_html=True)
        elif AVATAR_FILE.exists():
            st.image(str(AVATAR_FILE), width=160, caption="Default Avatar")
        else:
            st.markdown('<div style="width: 160px; height: 160px; border-radius: 50%; background: linear-gradient(135deg, #FF6B6B, #00D1FF); display: flex; align-items: center; justify-content: center; margin: 0 auto;"><span style="font-size: 4rem; color: white;">👤</span></div>', unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Profile picture upload
        st.markdown('<h4 class="card-title" style="text-align: center; margin-top: 1rem;">Profile Picture</h4>', unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader("Choose a profile picture", type=['png', 'jpg', 'jpeg'], key="profile_upload")
        
        if uploaded_file is not None:
            import base64
            from PIL import Image
            import io
            
            # Process the uploaded image
            try:
                # Open and resize image
                image = Image.open(uploaded_file)
                
                # Convert to RGB if necessary
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                
                # Resize image to 300x300 for storage efficiency
                image = image.resize((300, 300), Image.Resampling.LANCZOS)
                
                # Convert to base64
                buffered = io.BytesIO()
                image.save(buffered, format="JPEG", quality=85)
                img_str = base64.b64encode(buffered.getvalue()).decode()
                
                # Update in Firebase
                if st.button("📸 Update Profile Picture", key="update_pic"):
                    with st.spinner("Updating profile picture..."):
                        if update_user_profile_picture_firebase(user['uid'], img_str):
                            st.session_state.user_data['profile_picture'] = img_str
                            st.success("Profile picture updated successfully!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Failed to update profile picture.")
                
            except Exception as e:
                st.error(f"Error processing image: {e}")
        
        # Remove profile picture button
        if user.get('profile_picture'):
            if st.button("🗑️ Remove Picture", key="remove_pic"):
                if update_user_profile_picture_firebase(user['uid'], ""):
                    st.session_state.user_data['profile_picture'] = ""
                    st.success("Profile picture removed!")
                    time.sleep(1)
                    st.rerun()

    with col2:
        st.markdown('<h3 class="card-title">Account Details</h3>', unsafe_allow_html=True)
        
        st.write(f"**Name:** {user.get('full_name', 'N/A')}")
        st.write(f"**Username:** {user.get('username', 'N/A')}")
        st.write(f"**Email:** {user.get('email', 'N/A')}")
        
        st.write(f"**Member Since:** {user.get('created_at', 'N/A')[:10] if user.get('created_at') else 'N/A'}")
        
        
        
        

def feedback_page():
    """Enhanced feedback page with Firebase integration and rating system"""
    st.markdown('<h2 class="section-header">Feedback</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([1, 1])

    with col1:
        
        st.markdown('<h3 class="card-title">Send us your feedback</h3>', unsafe_allow_html=True)
        st.markdown('<p class="card-subtitle">Help us improve TravelViz with your valuable feedback</p>', unsafe_allow_html=True)
        
        with st.form("feedback_form"):
            name = st.text_input("Name *", value=st.session_state.user_data.get('full_name', ''))
            email = st.text_input("Email *", value=st.session_state.user_data.get('email', ''))
            
            # Rating system
            st.markdown("**Overall Rating ***")
            rating = st.selectbox("Rate your experience", 
                                options=[5, 4, 3, 2, 1], 
                                format_func=lambda x: f"⭐" * x + f" ({x}/5)",
                                index=0)
            
            # Feedback categories
            subject = st.selectbox("Feedback Category *", [
                "General Feedback",
                "Dashboard Issues", 
                "AI Insights",
                "Profile & Account",
                "Performance Issues",
                "Feature Request",
                "Bug Report",
                "Other"
            ])
            
            message_txt = st.text_area("Your Message *", height=150, 
                                    placeholder="Please describe your feedback, suggestions, or issues...")
            
            # Additional options
            follow_up = st.checkbox("I would like a follow-up response", value=True)
            newsletter = st.checkbox("Subscribe to TravelViz updates", value=False)
            
            submit_btn = st.form_submit_button("📤 Send Feedback", use_container_width=True)
            
            if submit_btn:
                if all([name, email, message_txt]):
                    with st.spinner("Sending your feedback..."):
                        time.sleep(1)  # Simulate processing
                        if save_feedback_firebase(name, email, subject, message_txt, rating):
                            st.success("✅ Thank you! Your feedback has been submitted successfully.")
                            st.balloons()  # Fun feedback animation
                        else:
                            st.error("❌ Failed to submit feedback. Please try again.")
                else:
                    st.warning("⚠️ Please fill all required fields!")
        
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        # FAQ Section
        st.markdown('<h3 class="card-title">Frequently Asked Questions</h3>', unsafe_allow_html=True)
        
        with st.expander("How do I access the dashboard?"):
            st.write("Navigate to the Dashboard tab in the sidebar menu. The Power BI dashboard will load automatically.")
        
        with st.expander("Can I export dashboard data?"):
            st.write("Yes, use the 'Open in New Tab' button on the dashboard page to access full Power BI features including export options.")
        
        with st.expander("How accurate is the AI insights?"):
            st.write("Our AI insights are based on real-time dashboard data and provide analysis of current travel trends and patterns.")
        
        with st.expander("How do I change my profile picture?"):
            st.write("Go to the Profile page and use the file uploader to select and upload your new profile picture.")
        
        st.markdown('</div>', unsafe_allow_html=True)

# ---------- Main Application ----------
def main():
    """Main application function"""
    init_session_state()
    inject_css()

    if not st.session_state.authenticated:
        login_signup_page()
        return

    # Force sidebar visibility with JavaScript
    st.markdown("""
    <script>
    // Ensure sidebar is always visible
    const sidebar = parent.document.querySelector('section[data-testid="stSidebar"]');
    if (sidebar) {
        sidebar.style.transform = 'translateX(0px)';
        sidebar.style.minWidth = '21rem';
        sidebar.style.maxWidth = '21rem';
        sidebar.style.width = '21rem';
    }
    
    // Hide collapse button if it exists
    const collapseBtn = parent.document.querySelector('[data-testid="collapsedControl"]');
    if (collapseBtn) {
        collapseBtn.style.display = 'none';
    }
    </script>
    """, unsafe_allow_html=True)

    # Sidebar navigation
    with st.sidebar:
        # Brand header
        user_name = st.session_state.user_data.get('full_name', 'User')
        st.markdown(
            f"""
            <div class="brand-head">
                <div class="brand">TravelViz</div>
                <div class="welcome">Welcome, {user_name}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Navigation menu - UPDATED ORDER (Always expanded)
        menu_options = ["Home", "Dashboard", "AI Insights", "Profile", "Feedback"]
        menu_icons = ["house", "graph-up", "robot", "person", "envelope"]
        
        selected = option_menu(
            menu_title=None,
            options=menu_options,
            icons=menu_icons,
            menu_icon="cast",
            default_index=0,
            styles={
                "container": {"padding": "0!important", "background-color": "transparent"},
                "icon": {"color": "#00D1FF", "font-size": "15px"},
                "nav-link": {
                    "font-size": "16px",
                    "text-align": "left",
                    "margin": "0px",
                    "padding": "1rem",
                    "border-radius": "15px",
                    "color": "white",
                    "background-color": "transparent",
                },
                "nav-link-selected": {
                    "background": "linear-gradient(45deg, #FF6B6B, #00D1FF)",
                    "color": "white",
                },
            },
        )

        # User actions (Logout) - Always visible
        st.markdown('<div class="user-actions">', unsafe_allow_html=True)
        
        if st.button("🚪 Logout", key="logout_btn", use_container_width=True):
            # Clear session state
            for key in ['authenticated', 'user_data', 'chat_history', 'force_nav']:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)

    # Handle forced navigation
    if st.session_state.force_nav:
        selected = st.session_state.force_nav
        st.session_state.force_nav = None

    # Route to appropriate page - UPDATED PAGE FUNCTIONS
    page_functions = {
        "Home": home_page,
        "Dashboard": dashboard_page,
        "AI Insights": insights_page,
        "Profile": profile_page,
        "Feedback": feedback_page
    }
    
    if selected in page_functions:
        page_functions[selected]()

if __name__ == "__main__":
    main()