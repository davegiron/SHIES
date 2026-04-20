# expert_eval.py - ISO/IEC 25010:2015 evaluation with descriptive ratings
import pandas as pd
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from io import BytesIO

EVAL_FILE = "expert_evaluations.csv"

# ISO/IEC 25010:2015 criteria from your proposal
ISO_25010_CRITERIA = {
    "Performance Efficiency": [
        "Time behaviour: Response and processing times meet requirements",
        "Resource utilization: System uses resources efficiently during encryption/key exchange",
        "Capacity: System handles multiple simultaneous requests"
    ],
    "Security": [
        "Confidentiality: System protects data from unauthorized access",
        "Integrity: System ensures data accuracy and prevents tampering during transmission",
        "Authenticity: System verifies identity of users/parties",
        "Accountability: System logs actions for traceability"
    ],
    "Functional Suitability": [
        "Functional completeness: System covers all specified tasks (request/approve/encrypt)",
        "Functional correctness: System provides correct results with needed precision",
        "Functional appropriateness: System facilitates patient-controlled access as intended"
    ]
}

LIKERT_SCALE = [1, 2, 3, 4, 5]

# Descriptive ratings per proposal methodology
def get_descriptive_rating(mean_score):
    """Convert mean score to descriptive rating per proposal"""
    if mean_score >= 4.5: return "Excellent"
    elif mean_score >= 3.5: return "Very Good"
    elif mean_score >= 2.5: return "Good"
    elif mean_score >= 1.5: return "Fair"
    else: return "Poor"

def save_evaluation(evaluator_name, evaluator_role, responses, comments=""):
    """Save expert evaluation to CSV with new ID format"""
    file_exists = os.path.isfile(EVAL_FILE)

    with open(EVAL_FILE, 'a', newline='') as f:
        # Flatten responses: category_criterion = score
        flat_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "evaluator_name": evaluator_name,
            "evaluator_role": evaluator_role,
            "evaluator_id": evaluator_role, # AD001_ADMIN, AD002_IT_EXPERT
            "comments": comments.replace(",", ";") # Avoid CSV breaks
        }
        for category, criteria in responses.items():
            for criterion, score in criteria.items():
                col_name = f"{category}__{criterion}"[:50] # Truncate for CSV
                flat_data[col_name] = score

        df = pd.DataFrame([flat_data])
        df.to_csv(f, header=not file_exists, index=False)

def get_eval_summary():
    """Return summary with mean, weighted mean, and descriptive rating"""
    if not os.path.isfile(EVAL_FILE):
        return pd.DataFrame()

    df = pd.read_csv(EVAL_FILE)
    # Get only numeric columns (the scores)
    score_cols = [c for c in df.columns if "__" in c]

    if not score_cols:
        return pd.DataFrame()

    # Calculate per-criterion stats
    summary = []
    for col in score_cols:
        category, criterion = col.split("__", 1)
        scores = df[col].dropna()
        if len(scores) > 0:
            mean = scores.mean()
            summary.append({
                "Category": category,
                "Criterion": criterion,
                "Mean Score": round(mean, 2),
                "Weighted Mean": round(mean, 2), # Same for now; can add weights later
                "Descriptive Rating": get_descriptive_rating(mean),
                "N": len(scores)
            })

    return pd.DataFrame(summary)

def generate_eval_pdf():
    """Generate PDF report of expert evaluations for Chapter 4 Appendix"""
    summary_df = get_eval_summary()
    if summary_df.empty:
        return None

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("ISO/IEC 25010:2015 Expert Evaluation Results", styles['Title']))
    elements.append(Paragraph("Secure Health Information Exchange System", styles['Heading2']))
    elements.append(Spacer(1, 12))

    # Overall score
    overall_mean = summary_df['Mean Score'].mean()
    overall_rating = get_descriptive_rating(overall_mean)
    elements.append(Paragraph(f"<b>Overall System Quality Score:</b> {overall_mean:.2f} / 5.0 ({overall_rating})", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Table per category
    for category in summary_df['Category'].unique():
        elements.append(Paragraph(f"<b>{category}</b>", styles['Heading3']))
        cat_df = summary_df[summary_df['Category'] == category][['Criterion', 'Mean Score', 'Descriptive Rating', 'N']]

        data = [cat_df.columns.tolist()] + cat_df.values.tolist()
        t = Table(data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

    doc.build(elements)
    buf.seek(0)
    return buf