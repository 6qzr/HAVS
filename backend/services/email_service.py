#!/usr/bin/env python3
"""
Email Service for ML Feedback
Sends feedback notifications to admin email
"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict, Optional


# Email Configuration
ADMIN_EMAIL = "qaisalj@gmail.com"  # Your email where feedback will be sent
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587


def send_feedback_email(
    predictions: List[Dict],
    general_comment: str = "",
    timestamp: str = ""
) -> bool:
    """
    Send ML feedback via email
    
    Args:
        predictions: List of prediction results with user ratings
        general_comment: Optional general feedback comment
        timestamp: Timestamp of feedback submission
        
    Returns:
        True if email sent successfully, False otherwise
    """
    
    # Get email credentials from environment variables
    sender_email = os.getenv("EMAIL_USER")
    sender_password = os.getenv("EMAIL_PASSWORD")
    
    if not sender_email or not sender_password:
        print("⚠️  Email credentials not configured!")
        print("   Set EMAIL_USER and EMAIL_PASSWORD environment variables")
        print("   Example: export EMAIL_USER='your.email@gmail.com'")
        print("   Example: export EMAIL_PASSWORD='your_app_password'")
        return False
    
    try:
        # Create email message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🔔 ML Feedback Received - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        msg['From'] = sender_email
        msg['To'] = ADMIN_EMAIL
        
        # Build email content
        html_content = build_html_email(predictions, general_comment, timestamp)
        text_content = build_text_email(predictions, general_comment, timestamp)
        
        # Attach both plain text and HTML versions
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Secure connection
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        print(f"✅ Feedback email sent successfully to {ADMIN_EMAIL}")
        return True
        
    except smtplib.SMTPAuthenticationError:
        print("❌ Email authentication failed. Check EMAIL_USER and EMAIL_PASSWORD")
        print("   For Gmail, you need to use an App Password:")
        print("   1. Go to Google Account Settings > Security")
        print("   2. Enable 2-Step Verification")
        print("   3. Create an App Password for 'Mail'")
        return False
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False


def build_html_email(predictions: List[Dict], general_comment: str, timestamp: str) -> str:
    """Build HTML version of feedback email"""
    
    # Count ratings
    correct_count = sum(1 for p in predictions if p.get('user_rating') == 'correct')
    incorrect_count = sum(1 for p in predictions if p.get('user_rating') == 'incorrect')
    unsure_count = sum(1 for p in predictions if p.get('user_rating') == 'unsure')
    no_rating_count = sum(1 for p in predictions if not p.get('user_rating'))
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .summary {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 4px solid #667eea;
        }}
        .summary h2 {{
            margin-top: 0;
            font-size: 18px;
            color: #667eea;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .stat-box {{
            background: white;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            margin-top: 5px;
        }}
        .predictions {{
            margin-bottom: 30px;
        }}
        .prediction-item {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        .prediction-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .filename {{
            font-weight: 600;
            color: #333;
            font-size: 16px;
        }}
        .badge {{
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-vulnerable {{
            background: #fee;
            color: #c00;
        }}
        .badge-safe {{
            background: #efe;
            color: #0a0;
        }}
        .prediction-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
        }}
        .detail-item {{
            font-size: 14px;
        }}
        .detail-label {{
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            display: block;
            margin-bottom: 4px;
        }}
        .detail-value {{
            color: #333;
            font-weight: 600;
        }}
        .rating {{
            padding: 15px;
            border-radius: 6px;
            margin-top: 10px;
        }}
        .rating-correct {{
            background: #d4edda;
            border-left: 4px solid #28a745;
        }}
        .rating-incorrect {{
            background: #f8d7da;
            border-left: 4px solid #dc3545;
        }}
        .rating-unsure {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
        }}
        .rating-none {{
            background: #e9ecef;
            border-left: 4px solid #6c757d;
        }}
        .rating-label {{
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .comment-section {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .comment-section h2 {{
            margin-top: 0;
            font-size: 18px;
            color: #667eea;
        }}
        .comment-text {{
            background: white;
            padding: 15px;
            border-radius: 6px;
            font-style: italic;
            color: #555;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
            text-align: center;
            color: #666;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔔 New ML Feedback Received</h1>
        <p>User feedback on vulnerability predictions</p>
        <p style="font-size: 14px;">Submitted: {timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Feedback Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">{len(predictions)}</div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{correct_count}</div>
                <div class="stat-label">✓ Correct</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{incorrect_count}</div>
                <div class="stat-label">✗ Incorrect</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{unsure_count}</div>
                <div class="stat-label">? Unsure</div>
            </div>
        </div>
    </div>
    
    <div class="predictions">
        <h2>📝 File Predictions & Ratings</h2>
"""
    
    # Add each prediction
    for pred in predictions:
        filename = pred.get('filename', 'Unknown')
        prediction = pred.get('prediction', 'Unknown')
        confidence = pred.get('confidence', 0) * 100
        user_rating = pred.get('user_rating')
        file_content = pred.get('file_content', '')
        
        prediction_class = 'vulnerable' if prediction == 'VULNERABLE' else 'safe'
        
        # Determine rating style
        if user_rating == 'correct':
            rating_class = 'rating-correct'
            rating_icon = '✓'
            rating_text = 'User confirmed: Correct'
        elif user_rating == 'incorrect':
            rating_class = 'rating-incorrect'
            rating_icon = '✗'
            rating_text = 'User reported: Incorrect'
        elif user_rating == 'unsure':
            rating_class = 'rating-unsure'
            rating_icon = '?'
            rating_text = 'User marked: Unsure'
        else:
            rating_class = 'rating-none'
            rating_icon = '—'
            rating_text = 'No rating provided'
        
        html += f"""
        <div class="prediction-item">
            <div class="prediction-header">
                <span class="filename">{filename}</span>
                <span class="badge badge-{prediction_class}">{prediction}</span>
            </div>
            <div class="prediction-details">
                <div class="detail-item">
                    <span class="detail-label">Model Prediction</span>
                    <span class="detail-value">{prediction}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Confidence</span>
                    <span class="detail-value">{confidence:.1f}%</span>
                </div>
            </div>
            <div class="rating {rating_class}">
                <span class="rating-label">{rating_icon} {rating_text}</span>
            </div>"""
        
        # Add code content if available
        if file_content and file_content.strip():
            # Truncate very long files (keep first 50 lines)
            lines = file_content.split('\n')
            if len(lines) > 50:
                display_content = '\n'.join(lines[:50])
                display_content += f'\n\n... ({len(lines) - 50} more lines truncated)'
            else:
                display_content = file_content
            
            # Escape HTML
            display_content = display_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            
            html += f"""
            <div style="margin-top: 15px;">
                <div style="font-size: 13px; font-weight: 600; color: #667eea; margin-bottom: 8px;">📄 Source Code:</div>
                <pre style="background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 12px; font-family: 'Courier New', monospace; line-height: 1.5; margin: 0;">{display_content}</pre>
            </div>"""
        
        html += """
        </div>
"""
    
    html += """
    </div>
"""
    
    # Add general comment if provided
    if general_comment and general_comment.strip():
        html += f"""
    <div class="comment-section">
        <h2>💬 Additional Comments</h2>
        <div class="comment-text">
            {general_comment}
        </div>
    </div>
"""
    
    html += """
    <div class="footer">
        <p>This feedback will help improve the ML model's accuracy.</p>
        <p>FYP Vulnerability Scanner · ML Feedback System</p>
    </div>
</body>
</html>
"""
    
    return html


def build_text_email(predictions: List[Dict], general_comment: str, timestamp: str) -> str:
    """Build plain text version of feedback email"""
    
    text = f"""
═══════════════════════════════════════════════════════════
  NEW ML FEEDBACK RECEIVED
═══════════════════════════════════════════════════════════

Submitted: {timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

FEEDBACK SUMMARY
───────────────────────────────────────────────────────────
Total Files: {len(predictions)}
Correct: {sum(1 for p in predictions if p.get('user_rating') == 'correct')}
Incorrect: {sum(1 for p in predictions if p.get('user_rating') == 'incorrect')}
Unsure: {sum(1 for p in predictions if p.get('user_rating') == 'unsure')}

FILE PREDICTIONS & RATINGS
───────────────────────────────────────────────────────────
"""
    
    for i, pred in enumerate(predictions, 1):
        filename = pred.get('filename', 'Unknown')
        prediction = pred.get('prediction', 'Unknown')
        confidence = pred.get('confidence', 0) * 100
        user_rating = pred.get('user_rating', 'none')
        file_content = pred.get('file_content', '')
        
        rating_symbols = {
            'correct': '✓ CORRECT',
            'incorrect': '✗ INCORRECT',
            'unsure': '? UNSURE',
            'none': '— NO RATING'
        }
        
        text += f"""
{i}. {filename}
   Model Prediction: {prediction} ({confidence:.1f}% confidence)
   User Rating: {rating_symbols.get(user_rating, '— NO RATING')}
"""
        
        # Add code content if available
        if file_content and file_content.strip():
            lines = file_content.split('\n')
            if len(lines) > 50:
                display_content = '\n   '.join(lines[:50])
                display_content += f'\n   ... ({len(lines) - 50} more lines truncated)'
            else:
                display_content = '\n   '.join(lines)
            
            text += f"""
   Source Code:
   ─────────────────────────────────────────────────
   {display_content}
   ─────────────────────────────────────────────────

"""
    
    if general_comment and general_comment.strip():
        text += f"""
ADDITIONAL COMMENTS
───────────────────────────────────────────────────────────
{general_comment}
"""
    
    text += """
═══════════════════════════════════════════════════════════
This feedback will help improve the ML model's accuracy.
FYP Vulnerability Scanner · ML Feedback System
═══════════════════════════════════════════════════════════
"""
    
    return text


# Test function
def test_email_service():
    """Test email service with sample data"""
    test_predictions = [
        {
            "filename": "app.py",
            "prediction": "VULNERABLE",
            "confidence": 0.89,
            "user_rating": "correct",
            "file_content": """def login(username, password):
    # VULNERABLE: SQL Injection
    query = "SELECT * FROM users WHERE username='" + username + "'"
    result = db.execute(query)
    return result

def get_user_data(user_id):
    # Safe: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))"""
        },
        {
            "filename": "utils.py",
            "prediction": "SAFE",
            "confidence": 0.76,
            "user_rating": "incorrect",
            "file_content": """def sanitize_input(user_input):
    # Remove special characters
    cleaned = re.sub(r'[^a-zA-Z0-9]', '', user_input)
    return cleaned

def hash_password(password):
    # Use bcrypt for password hashing
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())"""
        }
    ]
    
    test_comment = "The model detected SQL injection correctly in app.py but missed a potential buffer overflow in utils.py."
    test_timestamp = datetime.now().isoformat()
    
    success = send_feedback_email(test_predictions, test_comment, test_timestamp)
    
    if success:
        print("✅ Test email sent successfully!")
    else:
        print("❌ Test email failed. Check configuration.")


if __name__ == "__main__":
    # Run test when executed directly
    print("Testing email service...")
    test_email_service()

