import os
import logging
import tempfile
import json
import re
import gzip
import traceback
import sys
import io
import subprocess
import zipfile
import shutil
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
import pandas as pd

try:
    from openai import OpenAI
    # Initialize OpenAI client
    # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
    # do not change this unless explicitly requested by the user
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
    openai = None
    if OPENAI_API_KEY:
        openai = OpenAI(api_key=OPENAI_API_KEY)
except ImportError:
    openai = None
    OPENAI_API_KEY = None

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key")

# Configure upload settings
ALLOWED_EXTENSIONS = {'zip', 'csv', 'txt', 'json', 'xlsx', 'xls', 'pdf', 'gz', 'log'}

# Store assignment URLs for reference
ASSIGNMENT_URLS = [
    "https://exam.sanand.workers.dev/tds-2025-01-ga1",
    "https://exam.sanand.workers.dev/tds-2025-01-ga2",
    "https://exam.sanand.workers.dev/tds-2025-01-ga3",
    "https://exam.sanand.workers.dev/tds-2025-01-ga4",
    "https://exam.sanand.workers.dev/tds-2025-01-ga5"
]

###############################################
# Apache Log Processing Functions
###############################################

def parse_apache_log_line(line):
    """
    Parse a single Apache log line with custom format handling
    
    Args:
        line (str): A single line from an Apache log file
        
    Returns:
        dict: Parsed log entry or None if parsing failed
    """
    # Handle both string and bytes input
    if isinstance(line, bytes):
        try:
            line = line.decode('utf-8')
        except UnicodeDecodeError:
            line = line.decode('utf-8', errors='replace')
    
    # Skip empty lines
    if not line.strip():
        return None
    
    # Pattern matches standard Apache log format with vhost and server at the end
    pattern = re.compile(r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)" (\S+) (\S+)')
    
    match = pattern.search(line)
    if not match:
        # Try alternative format without quotes
        alt_pattern = re.compile(r'(\S+) (\S+) (\S+) \[(.*?)\] (.*?) (\d+) (\d+|-) (.*?) (.*?) (\S+) (\S+)')
        match = alt_pattern.search(line)
        if not match:
            return None
    
    # Extract components
    ip, remote_logname, remote_user, time_str, request, status, size, referer, user_agent, vhost, server = match.groups()
    
    # Parse request further
    method, url, protocol = "", "", ""
    request_parts = request.split(' ', 2)
    if len(request_parts) >= 3:
        method, url, protocol = request_parts
    elif len(request_parts) == 2:
        method, url = request_parts
    
    # Convert size to int if not '-'
    if size == '-':
        size = 0
    else:
        size = int(size)
    
    # Parse time string to datetime
    try:
        # Format: [day/month/year:hour:minute:second +timezone]
        time = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
    except ValueError:
        # Fallback for timestamp parsing errors
        time = None
    
    return {
        'ip': ip,
        'remote_logname': remote_logname,
        'remote_user': remote_user,
        'time_str': time_str,  # Original string
        'time': time,          # Parsed datetime if successful
        'method': method,
        'url': url,
        'protocol': protocol,
        'status': int(status),
        'size': size,
        'referer': referer,
        'user_agent': user_agent,
        'vhost': vhost,
        'server': server
    }

def count_carnatic_requests(log_file_path):
    """
    Count the number of successful GET requests for pages under /carnatic/ 
    from 17:00 until before 21:00 on Saturdays
    
    Args:
        log_file_path (str): Path to the Apache log file
        
    Returns:
        int: Count of matching requests
    """
    # Determine if the file is gzipped
    is_gzipped = log_file_path.lower().endswith('.gz')
    
    # Initialize count
    count = 0
    
    # Open file with appropriate handling for gzip
    if is_gzipped:
        file_obj = gzip.open(log_file_path, 'rt', encoding='utf-8', errors='replace')
    else:
        file_obj = open(log_file_path, 'r', encoding='utf-8', errors='replace')
    
    try:
        # Process each line
        for line in file_obj:
            entry = parse_apache_log_line(line)
            if not entry or not entry['time']:
                continue
            
            # Check if it's a Saturday (5 = Saturday in weekday())
            if entry['time'].weekday() == 5:
                # Check if time is between 17:00 and 21:00
                hour = entry['time'].hour
                if 17 <= hour < 21:
                    # Check if it's a successful GET request to /carnatic/
                    if (entry['method'] == 'GET' and 
                        entry['url'].startswith('/carnatic/') and 
                        200 <= entry['status'] < 300):
                        count += 1
    
    finally:
        file_obj.close()
    
    return count

def count_carnatic_requests_optimized(log_file_path):
    """
    Optimized version to count /carnatic/ GET requests on Saturdays 17:00-21:00
    This avoids pandas and uses direct matching for better performance on large files
    
    Args:
        log_file_path (str): Path to the Apache log file (can be gzipped)
        
    Returns:
        int: Count of matching requests
    """
    # Determine if the file is gzipped
    is_gzipped = log_file_path.lower().endswith('.gz')
    
    # Precompile patterns for better performance
    log_pattern = re.compile(r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+|-)')
    carnatic_pattern = re.compile(r'^/carnatic/')
    
    # Initialize count
    count = 0
    
    try:
        # Open file with appropriate handling for gzip in binary mode for better handling
        if is_gzipped:
            with gzip.open(log_file_path, 'rb') as file:
                for line in file:
                    # Quick pre-filtering to avoid expensive operations
                    # Check if line contains both 'carnatic' and 'GET' before parsing
                    try:
                        line_str = line.decode('utf-8', errors='replace')
                        if 'carnatic' not in line_str or 'GET' not in line_str:
                            continue
                        
                        # Parse the line
                        match = log_pattern.search(line_str)
                        if not match:
                            continue
                        
                        # Extract components
                        ip, remote_logname, remote_user, time_str, request, status, size = match.groups()
                        
                        # Parse request further
                        request_parts = request.split(' ', 2)
                        if len(request_parts) < 2:
                            continue
                        
                        method, url = request_parts[0], request_parts[1]
                        
                        # Check if it's a GET request to /carnatic/
                        if method != 'GET' or not carnatic_pattern.match(url):
                            continue
                        
                        # Check status code
                        status = int(status)
                        if not (200 <= status < 300):
                            continue
                        
                        # Parse time string
                        try:
                            # Format: day/month/year:hour:minute:second +timezone
                            time_obj = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
                            
                            # Check if it's a Saturday (5 = Saturday)
                            if time_obj.weekday() != 5:
                                continue
                            
                            # Check if time is between 17:00 and 21:00
                            hour = time_obj.hour
                            if not (17 <= hour < 21):
                                continue
                            
                            # If all conditions pass, increment count
                            count += 1
                            
                        except ValueError:
                            # Skip if date parsing fails
                            continue
                    except UnicodeDecodeError:
                        # Skip if line decoding fails
                        continue
        else:
            # For non-gzipped files
            with open(log_file_path, 'r', encoding='utf-8', errors='replace') as file:
                for line in file:
                    # Skip lines without required keywords
                    if 'carnatic' not in line or 'GET' not in line:
                        continue
                    
                    # Parse the line
                    match = log_pattern.search(line)
                    if not match:
                        continue
                    
                    # Extract components
                    ip, remote_logname, remote_user, time_str, request, status, size = match.groups()
                    
                    # Parse request further
                    request_parts = request.split(' ', 2)
                    if len(request_parts) < 2:
                        continue
                    
                    method, url = request_parts[0], request_parts[1]
                    
                    # Check if it's a GET request to /carnatic/
                    if method != 'GET' or not carnatic_pattern.match(url):
                        continue
                    
                    # Check status code
                    status = int(status)
                    if not (200 <= status < 300):
                        continue
                    
                    # Parse time string
                    try:
                        time_obj = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
                        
                        # Check if it's a Saturday
                        if time_obj.weekday() != 5:
                            continue
                        
                        # Check if time is between 17:00 and 21:00
                        hour = time_obj.hour
                        if not (17 <= hour < 21):
                            continue
                        
                        # If all conditions pass, increment count
                        count += 1
                        
                    except ValueError:
                        # Skip if date parsing fails
                        continue
                    
        return count
    
    except Exception as e:
        logger.error(f"Error counting Carnatic requests: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def analyze_telugu_bandwidth(log_file_path, target_date="2024-05-31"):
    """
    Analyze telugump3 bandwidth usage for a specific date
    
    Args:
        log_file_path (str): Path to the gzipped Apache log file
        target_date (str): Date in format YYYY-MM-DD to filter logs
        
    Returns:
        tuple: (top_ip, total_bytes) - IP with highest download volume and its total bytes
    """
    # Compile regex patterns for better performance
    log_pattern = re.compile(r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)" (\S+) (\S+)')
    telugu_pattern = re.compile(r'^/telugump3/')
    
    # Track bytes downloaded by each IP
    ip_bytes = defaultdict(int)
    
    # Track overall metrics
    total_lines = 0
    processed_lines = 0
    matching_date_lines = 0
    matching_url_lines = 0
    final_matches = 0
    
    # Parse the target date string
    target_date_obj = datetime.strptime(target_date, "%Y-%m-%d").date()
    
    try:
        logger.info(f"Starting analysis of {log_file_path}")
        logger.info(f"Filtering for /telugump3/ URLs on {target_date}")
        
        with gzip.open(log_file_path, 'rb') as file:
            for binary_line in file:
                total_lines += 1
                
                if total_lines % 50000 == 0:
                    logger.info(f"Processed {total_lines} lines...")
                
                # Decode the binary line to string with error handling
                line = binary_line.decode('utf-8', errors='replace')
                
                # Quick pre-filtering to avoid expensive operations on non-matching lines
                if 'telugump3' not in line:
                    continue
                
                processed_lines += 1
                
                # Parse the line
                match = log_pattern.search(line)
                if not match:
                    continue
                
                # Extract the components
                ip = match.group(1)
                time_str = match.group(4)
                request = match.group(5)
                status = int(match.group(6))
                size_str = match.group(7)
                
                # Parse size
                size = int(size_str) if size_str != '-' else 0
                
                # Parse time
                try:
                    timestamp = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
                    log_date = timestamp.date()
                    
                    # Check if date matches target date
                    if log_date != target_date_obj:
                        continue
                    
                    matching_date_lines += 1
                    
                    # Split request into method, url, protocol
                    request_parts = request.split(' ', 2)
                    if len(request_parts) < 2:
                        continue
                    
                    method, url = request_parts[0], request_parts[1]
                    
                    # Check if URL starts with /telugump3/
                    if not telugu_pattern.match(url):
                        continue
                    
                    matching_url_lines += 1
                    
                    # Check for successful requests
                    if 200 <= status < 300:
                        # Add bytes to the IP's total
                        ip_bytes[ip] += size
                        final_matches += 1
                
                except ValueError:
                    # Skip if date parsing fails
                    continue
        
        # Find the IP with the highest bytes downloaded
        if ip_bytes:
            top_ip = max(ip_bytes.items(), key=lambda x: x[1])
            
            logger.info(f"Total lines processed: {total_lines}")
            logger.info(f"Lines containing 'telugump3': {processed_lines}")
            logger.info(f"Lines matching date {target_date}: {matching_date_lines}")
            logger.info(f"Lines with URL starting with /telugump3/: {matching_url_lines}")
            logger.info(f"Final matching successful requests: {final_matches}")
            logger.info(f"Unique IPs downloading from /telugump3/: {len(ip_bytes)}")
            logger.info(f"Top bandwidth consumer: {top_ip[0]} with {top_ip[1]} bytes")
            
            # Also log the top 5 IPs by bandwidth
            logger.info("Top 5 bandwidth consumers:")
            for ip, bytes_downloaded in sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:5]:
                logger.info(f"  {ip}: {bytes_downloaded} bytes")
            
            return top_ip
        else:
            logger.warning("No matching entries found!")
            return None, 0
    
    except Exception as e:
        logger.error(f"Error analyzing log file: {str(e)}")
        return None, 0

###############################################
# Student Data Processing Functions
###############################################

def count_unique_student_ids(file_path):
    """
    Process a text file containing student records and count unique student IDs.
    
    Args:
        file_path (str): Path to the text file with student records
        
    Returns:
        int: Number of unique student IDs in the file
    """
    try:
        unique_ids = set()
        
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            # Read all lines in the file
            for line in file:
                line = line.strip()
                
                # Skip empty lines or header lines
                if not line or line.startswith('#') or 'student_id' in line.lower():
                    continue
                
                # Extract student ID - assume first field is student ID
                fields = line.split(',')
                if len(fields) >= 1:
                    student_id = fields[0].strip()
                    if student_id and student_id != 'student_id':
                        unique_ids.add(student_id)
        
        return len(unique_ids)
    except Exception as e:
        logger.error(f"Error counting unique student IDs: {str(e)}")
        return f"Error: {str(e)}"

###############################################
# GA5 - RetailWise Sales Data Processing
###############################################

def standardize_country(country):
    """Convert various country formats to standard 2-letter codes"""
    if not country or pd.isna(country):
        return None
    
    # Country mapping for commonly used values
    country_mapping = {
        'France': 'FR',
        'FR': 'FR',
        'FRANCE': 'FR',
        'FRA': 'FR',
        'United States': 'US',
        'USA': 'US',
        'US': 'US',
        'United Kingdom': 'UK',
        'UK': 'UK',
        'GB': 'UK',
        'Germany': 'DE',
        'DE': 'DE',
        'GER': 'DE',
        'Japan': 'JP',
        'JP': 'JP',
        'Canada': 'CA',
        'CA': 'CA',
        'India': 'IN',
        'IN': 'IN'
    }
    
    # Return mapped value if it exists, otherwise return original
    return country_mapping.get(str(country).strip(), str(country).strip())

def parse_date(date_str):
    """Convert various date formats to a standard datetime object"""
    if not date_str or pd.isna(date_str):
        return None
    
    # Convert to string if it's not already
    if not isinstance(date_str, str):
        date_str = str(date_str)
    
    date_str = date_str.strip()
    
    # Try multiple date formats
    formats = [
        '%Y-%m-%d',
        '%d/%m/%Y',
        '%m/%d/%Y',
        '%d-%m-%Y',
        '%m-%d-%Y',
        '%b %d, %Y',
        '%d %b %Y'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).date()
        except ValueError:
            continue
    
    return None

def extract_product_name(product_code):
    """Extract the product name before the slash"""
    if not product_code or pd.isna(product_code):
        return None
    
    if '/' in product_code:
        return product_code.split('/')[0].strip()
    return product_code.strip()

def clean_numeric_value(value):
    """Remove 'USD' and spaces, convert to float"""
    if not value or pd.isna(value):
        return 0.0
    
    if isinstance(value, (int, float)):
        return float(value)
    
    # Convert to string and clean
    value_str = str(value).strip()
    value_str = value_str.replace('USD', '').replace('$', '').replace(',', '').strip()
    
    try:
        return float(value_str)
    except ValueError:
        return 0.0

def calculate_margin_for_retailwise(excel_file_path, cutoff_date_str=None, product_filter='Kappa', country_filter='FR'):
    """
    Calculate the margin for RetailWise Inc data
    
    Args:
        excel_file_path (str): Path to the Excel file
        cutoff_date_str (str, optional): Cutoff date in string format to filter transactions
        product_filter (str, optional): Filter for a specific product. Default is 'Kappa'
        country_filter (str, optional): Filter for a specific country. Default is 'FR'
        
    Returns:
        float: The calculated margin as a percentage
    """
    try:
        # Read the Excel file
        df = pd.read_excel(excel_file_path)
        
        # Parse cutoff date if provided
        cutoff_date = None
        if cutoff_date_str:
            cutoff_date = parse_date(cutoff_date_str)
            logger.info(f"Filtering transactions before {cutoff_date}")
        
        # Clean up data
        # 1. Standardize country codes
        df['Country'] = df['Country'].apply(standardize_country)
        
        # 2. Parse dates
        df['Date'] = df['Date'].apply(parse_date)
        
        # 3. Extract product names
        df['Product'] = df['Product Code'].apply(extract_product_name)
        
        # 4. Clean revenue and cost values
        df['Revenue (USD)'] = df['Revenue (USD)'].apply(clean_numeric_value)
        df['Cost (USD)'] = df['Cost (USD)'].apply(clean_numeric_value)
        
        # Apply filters
        filtered_df = df.copy()
        
        # Filter by product
        if product_filter:
            filtered_df = filtered_df[filtered_df['Product'] == product_filter]
            logger.info(f"Filtered to {len(filtered_df)} rows for product {product_filter}")
        
        # Filter by country
        if country_filter:
            filtered_df = filtered_df[filtered_df['Country'] == country_filter]
            logger.info(f"Filtered to {len(filtered_df)} rows for country {country_filter}")
        
        # Filter by date
        if cutoff_date:
            filtered_df = filtered_df[filtered_df['Date'] < cutoff_date]
            logger.info(f"Filtered to {len(filtered_df)} rows for dates before {cutoff_date}")
        
        # Check if we have data after filtering
        if len(filtered_df) == 0:
            return "Error: No data available after applying filters"
        
        # Calculate the margin
        total_revenue = filtered_df['Revenue (USD)'].sum()
        total_cost = filtered_df['Cost (USD)'].sum()
        
        if total_revenue == 0:
            return "Error: Total revenue is zero, cannot calculate margin"
        
        margin = (total_revenue - total_cost) / total_revenue
        
        logger.info(f"Calculated margin: {margin:.4f} ({margin*100:.2f}%)")
        logger.info(f"Based on total revenue: {total_revenue} USD and total cost: {total_cost} USD")
        
        return str(margin)
    
    except Exception as e:
        logger.error(f"Error calculating margin: {str(e)}")
        logger.error(traceback.format_exc())
        return f"Error: {str(e)}"

###############################################
# OpenAI Integration
###############################################

def execute_python_code(code, file_paths=None):
    """
    Execute the Python code generated by OpenAI against the uploaded files
    
    Args:
        code (str): Python code to execute
        file_paths (list, optional): List of file paths to make available to the code
        
    Returns:
        str: The output of the execution
    """
    try:
        # Create a temporary file to hold the code
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
            # Indent the code properly
            indented_code = "\n".join("    " + line for line in code.splitlines())
            
            # Modify the code to restrict file access to only the provided files
            # and add safety measures
            safe_code = f"""
import sys
import os
import pandas as pd
import numpy as np
import re
import json
from datetime import datetime
import math
import csv
import io

# Define allowed file paths
ALLOWED_FILES = {file_paths or []}

# Function to safely open files
def safe_open(file_path, mode='r', **kwargs):
    # Check if file is in allowed list
    if file_path not in ALLOWED_FILES:
        raise ValueError(f"Access to file {{file_path}} is not allowed")
    return open(file_path, mode, **kwargs)

# Function to safely read CSV
def safe_read_csv(file_path, **kwargs):
    if file_path not in ALLOWED_FILES:
        raise ValueError(f"Access to file {{file_path}} is not allowed")
    return pd.read_csv(file_path, **kwargs)

# Function to safely read Excel
def safe_read_excel(file_path, **kwargs):
    if file_path not in ALLOWED_FILES:
        raise ValueError(f"Access to file {{file_path}} is not allowed")
    return pd.read_excel(file_path, **kwargs)

# Override built-in open function for safety
open = safe_open
pd.read_csv = safe_read_csv
pd.read_excel = safe_read_excel

# Output buffer to capture print statements
output_buffer = io.StringIO()
sys.stdout = output_buffer

# The actual code starts here
try:
{indented_code}
except Exception as e:
    print(f"Error executing code: {{str(e)}}")

# Get the output
sys.stdout = sys.__stdout__
result = output_buffer.getvalue()
print(result)  # Only for debugging
            """
            
            # Write the safe code to the temporary file
            f.write(safe_code)
            temp_file_path = f.name
        
        # Execute the code in a subprocess with a timeout
        result = subprocess.run(
            [sys.executable, temp_file_path], 
            capture_output=True, 
            text=True, 
            timeout=30  # Set a reasonable timeout
        )
        
        # Get the output
        if result.returncode != 0:
            logger.error(f"Code execution failed: {result.stderr}")
            return f"Error executing code: {result.stderr}"
        
        # Clean the output (remove any debug prints from our wrapper)
        output = result.stdout.strip()
        
        # Delete the temporary file
        os.unlink(temp_file_path)
        
        return output
    
    except subprocess.TimeoutExpired:
        logger.error("Code execution timed out")
        return "Error: Code execution timed out"
    except Exception as e:
        logger.error(f"Error executing Python code: {str(e)}")
        return f"Error executing Python code: {str(e)}"

def answer_question(question, file_data=None):
    """
    Use OpenAI's GPT-4o model to answer the question using an agent-like approach:
    1. First, ask OpenAI what preprocessing is needed
    2. Execute any preprocessing instructions
    3. Return to OpenAI with the processed data to get the final answer
    
    Args:
        question (str): The question from the assignment
        file_data (dict, optional): Data extracted from uploaded files
        
    Returns:
        str: The answer to the question
    """
    # Handle direct answers from pre-processing
    # Check for GA5 RetailWise margin question and direct answer - more flexible matching
    if "margin" in question.lower() and "Kappa" in question and "FR" in question:
        logger.info("Detected retail sales margin calculation question from GA5")
        
        # If we have the direct result from file_processor
        if file_data and isinstance(file_data, dict) and "ga5_retailwise_margin" in file_data:
            margin_result = file_data["ga5_retailwise_margin"]
            logger.info(f"Returning direct margin calculation: {margin_result}")
            return margin_result
    
    # Check for Apache log Carnatic request count direct answer
    if "/carnatic/" in question and ("Saturday" in question or "Saturdays" in question):
        if file_data and isinstance(file_data, dict) and "carnatic_request_count" in file_data:
            count = file_data["carnatic_request_count"]
            logger.info(f"Returning direct Carnatic request count: {count}")
            return str(count)
    
    # Check for student ID count direct answer
    if "student" in question.lower() and "unique" in question.lower() and "ID" in question:
        if file_data and isinstance(file_data, dict) and "unique_student_ids_count" in file_data:
            count = file_data["unique_student_ids_count"]
            logger.info(f"Returning direct unique student ID count: {count}")
            return str(count)
            
    # Check for Telugu bandwidth bytes direct answer
    if "telugump3" in question.lower() and ("bandwidth" in question.lower() or "bytes" in question.lower()):
        if file_data and isinstance(file_data, dict) and "telugu_bandwidth_bytes" in file_data:
            bytes_count = file_data["telugu_bandwidth_bytes"]
            logger.info(f"Returning direct Telugu bandwidth bytes: {bytes_count}")
            return str(bytes_count)
    
    # Check if OpenAI client is available
    if not OPENAI_API_KEY or not openai:
        logger.warning("OpenAI API key is not set. API is working but cannot provide real answers.")
        
        # Process file data if available
        if file_data and isinstance(file_data, dict):
            # For CSV files with an answer column, try to extract answers directly
            if file_data:
                for file_name, content in file_data.items():
                    # Check for 'answer_column' key directly in file_data contents
                    if isinstance(content, dict) and 'answer_column' in content:
                        answer_values = content['answer_column']
                        if answer_values and len(answer_values) > 0:
                            return str(answer_values[0])
                    
                    # Check for ZIP files with main_csv that has answer column
                    if isinstance(content, dict) and 'main_csv' in content:
                        main_csv = content['main_csv']
                        if isinstance(main_csv, dict) and 'answer_column' in main_csv:
                            answer_values = main_csv['answer_column']
                            if answer_values and len(answer_values) > 0:
                                return str(answer_values[0])
        
        # Return placeholder for API demonstration purposes
        return "API is functioning correctly, but an OpenAI API key is required for generating actual answers. Add OPENAI_API_KEY to environment variables."
    
    try:
        # Step 1: Ask OpenAI what preprocessing is needed and if Python code is required
        planning_system_prompt = """
        You are an AI assistant helping determine what solution approach is needed
        to answer a question from a graded assignment. The question may involve analyzing 
        file data or performing calculations.
        
        For each question, determine:
        1. If a programmatic solution using Python is required
        2. What preprocessing steps are needed (if any)
        3. If additional calculations or manipulations are needed on the file data
        4. If the answer can be extracted directly from the data
        
        Return your response in JSON format with these fields:
        {
            "python_code_required": true/false,
            "preprocessing_needed": true/false,
            "preprocessing_steps": [list of specific steps],
            "answer_extraction_path": "path to answer if directly available in the data",
            "custom_calculation_description": "detailed description of calculation needed"
        }
        
        Be concise but specific in your instructions.
        Never recommend uploading or sharing the raw data with the language model.
        Instead, always prefer using Python code to process the data locally when needed.
        """
        
        # First user message asks for planning
        planning_user_content = f"Question: {question}\n\n"
        
        if file_data:
            planning_user_content += "Available file data summary:\n"
            # Only include a summary to prevent token limit issues
            if isinstance(file_data, dict):
                file_summary = {}
                for k, v in file_data.items():
                    if isinstance(v, dict):
                        if "columns" in v:
                            file_summary[k] = {"type": "tabular", "columns": v["columns"], "rows": v.get("rows", "unknown")}
                        elif "sheets" in v:
                            sheets_info = {}
                            for sheet_name, sheet_data in v["sheets"].items():
                                if isinstance(sheet_data, dict) and "columns" in sheet_data:
                                    sheets_info[sheet_name] = {"columns": sheet_data["columns"], "rows": sheet_data.get("rows", "unknown")}
                            file_summary[k] = {"type": "excel", "sheets": sheets_info}
                        elif "content" in v and isinstance(v["content"], str):
                            file_summary[k] = {"type": "text", "size": f"{len(v['content'])} chars"}
                        else:
                            file_summary[k] = {"type": "unknown"}
                    else:
                        file_summary[k] = {"type": "unknown"}
                planning_user_content += json.dumps(file_summary, indent=2)
            else:
                planning_user_content += "File data available but in non-dictionary format."
        else:
            planning_user_content += "No file data available."
        
        planning_user_content += "\n\nWhat preprocessing steps are needed for this question?"
        
        logger.debug(f"Sending planning request to OpenAI: {planning_user_content[:200]}...")
        
        # Make the planning API call
        planning_response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": planning_system_prompt},
                {"role": "user", "content": planning_user_content}
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
            max_tokens=500
        )
        
        planning_result = json.loads(planning_response.choices[0].message.content.strip())
        logger.debug(f"Planning response: {planning_result}")
        
        # Step 2: Check if we need to generate and execute Python code or do simple preprocessing
        processed_data = file_data.copy() if file_data else {}
        processed_data["planning_result"] = planning_result
        
        # If Python code is required
        if planning_result.get("python_code_required", False):
            logger.info("Python code generation required based on OpenAI suggestion")
            
            # Collect file paths for the code to access (if any)
            available_file_paths = []
            if file_data and isinstance(file_data, dict) and '_file_paths' in file_data:
                available_file_paths = file_data['_file_paths']
            
            # Request Python code from OpenAI
            code_system_prompt = """
            You are an expert Python programmer helping to solve a technical assignment.
            The user will provide a question and a description of available data files.
            Write a complete Python program that:

            1. Uses pandas, numpy, and other standard libraries as needed
            2. Processes the input files to compute the exact answer
            3. Only accesses the specified file paths and doesn't attempt to read other files
            4. Carefully handles file encoding issues and various data formats
            5. Follows best practices for error handling
            6. Prints only the final numerical answer without any explanations or text
               - If the answer should be a percentage, format it as XX.XX% (e.g. 42.10%)
               - If the answer is a simple number, print just the number
               - If the answer is text, print just the text answer without quotes or formatting
            
            Your code will be executed in a secure environment with access only to the specified files,
            and the output will be captured and returned directly to the user.
            
            Don't include any explanations in your response - just provide the working Python code.
            """
            
            # Include data summary for code generation
            file_info = "Available files and their content types:\n"
            if file_data and isinstance(file_data, dict):
                for file_name, data in file_data.items():
                    if file_name != '_file_paths' and not file_name.startswith('_'):
                        if isinstance(data, dict):
                            if 'columns' in data:
                                columns_str = ', '.join(data.get('columns', [])[:5])
                                file_info += f"- {file_name}: CSV with columns: {columns_str}...\n"
                            elif 'sheets' in data and isinstance(data['sheets'], dict):
                                sheet_names = list(data['sheets'].keys())
                                file_info += f"- {file_name}: Excel file with sheets: {', '.join(sheet_names)}\n"
                                # Include some column info for the first sheet
                                if sheet_names and 'columns' in data['sheets'].get(sheet_names[0], {}):
                                    first_sheet = sheet_names[0]
                                    columns_str = ', '.join(data['sheets'][first_sheet].get('columns', [])[:5])
                                    file_info += f"  - Sheet '{first_sheet}' has columns: {columns_str}...\n"
                            elif 'content' in data and isinstance(data['content'], str):
                                content_preview = data['content'][:100] + "..." if len(data['content']) > 100 else data['content']
                                file_info += f"- {file_name}: Text file, preview: {content_preview}\n"
                            else:
                                file_info += f"- {file_name}: Unknown format\n"
            
            code_user_content = f"""
            Question: {question}
            
            {file_info}
            
            Write a Python program to solve this problem. Remember:
            1. The program should compute and print only the final answer
            2. File paths will be provided as inputs to your code
            3. Do not include any explanations, only the working Python code
            4. The code will be executed in an isolated environment
            5. Use pandas and other standard libraries to process the data efficiently
            """
            
            logger.debug(f"Sending code generation request to OpenAI: {code_user_content[:200]}...")
            
            # Make the code generation API call
            code_response = openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": code_system_prompt},
                    {"role": "user", "content": code_user_content}
                ],
                temperature=0.1,
                max_tokens=1500
            )
            
            python_code = code_response.choices[0].message.content.strip()
            logger.debug(f"Received Python code from OpenAI: {python_code[:100]}...")
            
            # Extract code from any code blocks if present
            if "```python" in python_code:
                # Extract code from the markdown code block
                code_blocks = re.findall(r'```python\n(.*?)\n```', python_code, re.DOTALL)
                if code_blocks:
                    python_code = code_blocks[0]
            elif "```" in python_code:
                # Extract code from generic code block
                code_blocks = re.findall(r'```\n(.*?)\n```', python_code, re.DOTALL)
                if code_blocks:
                    python_code = code_blocks[0]
            
            # Save the original code for reference
            processed_data["generated_python_code"] = python_code
            
            # Execute the Python code with the file paths
            logger.info("Executing generated Python code")
            code_output = execute_python_code(python_code, available_file_paths)
            
            # Process the output
            logger.info(f"Python code execution output: {code_output}")
            processed_data["python_code_output"] = code_output
            
            # If the code execution was successful, use the output as the answer
            if not code_output.startswith("Error"):
                # Clean the output - remove any trailing whitespace, etc.
                answer = code_output.strip()
                logger.info(f"Using Python code output as answer: {answer}")
                return answer
        
        # Standard preprocessing if no Python code needed or if Python code failed
        if planning_result.get("preprocessing_needed", False):
            logger.info("Standard preprocessing needed based on OpenAI suggestion")
            
            # Check if there's a direct extraction path for the answer
            extraction_path = planning_result.get("answer_extraction_path")
            if extraction_path and isinstance(extraction_path, str):
                logger.info(f"Attempting to extract answer using path: {extraction_path}")
                # Try to follow the path to extract the answer
                # This is a simplified version - in practice, would need more robust path parsing
                path_parts = extraction_path.split('.')
                current = processed_data
                for part in path_parts:
                    if isinstance(current, dict) and part in current:
                        current = current[part]
                    else:
                        logger.warning(f"Could not follow extraction path at part: {part}")
                        current = None
                        break
                
                if current is not None:
                    logger.info(f"Successfully extracted answer: {current}")
                    return str(current)
        
        # Step 3: Get final answer from OpenAI with processed data
        final_system_prompt = """
        You are an expert assistant helping with technical graded assignments for the TDS 2025 course, specifically:
        
        - GA1: Data Science Fundamentals - statistical analysis, correlation/regression, pandas, numerical computing
        - GA2: Deployment Tools - image compression, GitHub Pages, Google Colab, Vercel, Docker, FastAPI, LLM deployment
        - GA5: Retail Analytics - data cleaning, margin calculations, standardizing country and date formats
        
        Assignment formats:
        1. File Analysis: Provide exact results from analyzing data files (averages, correlations, maximum values)
        2. Code Fixing: Correct provided code snippets and explain the exact output after fixing
        3. Command Line Tools: Give specific command line tools or commands for tasks
        4. Deployment Tasks: Provide implementation steps or URLs for deployment tasks
        5. Data Cleaning: Clean and process data with specific cleaning steps for different column types
        
        For all questions:
        - Answer directly without explanations, suitable for direct submission
        - For code fixes, identify the exact error and describe the precise output after fixing
        - For commands, show the correct command line syntax without explanation
        - For image analysis, give specific numerical answers based on pixel counts/properties
        - For URLs, provide precise, correctly formatted URLs
        - For quantitative analysis, provide just the final numerical result
        
        Return only the required answer in the most concise form possible.
        """
        
        # Include processed data in a format that doesn't exceed token limits
        final_user_content = f"Question: {question}\n\n"
        final_user_content += "Results of preprocessing:\n"
        
        # Add execution results from Python code if available
        if "python_code_output" in processed_data:
            final_user_content += f"Python code execution result: {processed_data['python_code_output']}\n\n"
        
        # Add specific preprocessing results
        if planning_result and "preprocessing_steps" in planning_result:
            final_user_content += "Preprocessing steps completed:\n"
            for step in planning_result["preprocessing_steps"]:
                final_user_content += f"- {step}\n"
            final_user_content += "\n"
        
        final_user_content += "Based on the preprocessing results, what is the final answer to the question? Provide only the answer in the most concise form possible (just the value or result without explanation)."
        
        logger.debug(f"Sending final request to OpenAI: {final_user_content[:200]}...")
        
        # Make the final API call
        final_response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": final_system_prompt},
                {"role": "user", "content": final_user_content}
            ],
            temperature=0.1,
            max_tokens=500
        )
        
        final_answer = final_response.choices[0].message.content.strip()
        logger.info(f"Final answer from OpenAI: {final_answer}")
        
        # Clean up the final answer (remove any "The answer is:" prefixes, etc.)
        final_answer = re.sub(r'^(The answer is:?|Answer:?)\s*', '', final_answer, flags=re.IGNORECASE)
        final_answer = final_answer.strip()
        
        return final_answer
    
    except Exception as e:
        logger.error(f"Error getting answer from OpenAI: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Fallback to any direct extraction results from file_data if OpenAI API failed
        if file_data and isinstance(file_data, dict):
            # Process each key for direct answers
            for key in ["ga5_retailwise_margin", "carnatic_request_count", "unique_student_ids_count", "telugu_bandwidth_bytes"]:
                if key in file_data:
                    return str(file_data[key])
        
        return f"Error: {str(e)}"

###############################################
# File Processing
###############################################

def process_files(file_paths, question):
    """
    Process uploaded files based on their type and extract relevant data
    
    Args:
        file_paths (list): List of paths to uploaded files
        question (str): The question to help determine processing strategy
        
    Returns:
        dict: Extracted data from files
    """
    results = {}
    
    try:
        # Check for GA5 RetailWise question
        if "RetailWise" in question and "margin" in question.lower() and "Kappa" in question and "FR" in question:
            logger.info("Detected RetailWise margin calculation question from GA5")
            
            # Look for the Excel file
            for file_path in file_paths:
                file_name = os.path.basename(file_path)
                file_ext = os.path.splitext(file_name)[1].lower()
                
                if file_ext in ['.xlsx', '.xls'] and 'sales' in file_name.lower():
                    # Extract the date from the question if present
                    cutoff_date = None
                    date_match = re.search(r'before\s+(.*?)\s+for', question)
                    if date_match:
                        cutoff_date = date_match.group(1).strip()
                        logger.info(f"Extracted cutoff date from question: {cutoff_date}")
                    
                    # Calculate the margin directly with date filter
                    margin = calculate_margin_for_retailwise(file_path, cutoff_date_str=cutoff_date)
                    
                    # Return the margin value directly for this specific question
                    if isinstance(margin, str) and not margin.startswith("Error"):
                        # Return as percentage as required
                        margin_pct = f"{float(margin) * 100:.2f}%"
                        return {"ga5_retailwise_margin": margin_pct}
                    else:
                        # If there was an error, include the Excel data for backup
                        excel_results = process_excel_file(file_path)
                        results[file_name] = excel_results
                        results["error"] = f"Failed to calculate margin directly: {margin}"
        
        # Check for Apache log analysis regarding Carnatic requests
        elif ("/carnatic/" in question and 
              ("successful" in question.lower() or "GET" in question) and
              ("17:00" in question or "17" in question) and 
              ("21:00" in question or "21" in question or "9" in question) and
              ("Saturday" in question or "Saturdays" in question)):
            logger.info("Detected Apache log analysis question for Carnatic requests")
            
            # Look for Apache log file (.log or .gz extension)
            for file_path in file_paths:
                file_name = os.path.basename(file_path)
                file_ext = os.path.splitext(file_name)[1].lower()
                
                if file_ext in ['.log', '.gz'] or 'log' in file_name.lower():
                    # Try the optimized method first (better performance for large files)
                    try:
                        request_count = count_carnatic_requests_optimized(file_path)
                        if isinstance(request_count, int):
                            logger.info(f"Found {request_count} matching Carnatic GET requests (optimized method)")
                            return {"carnatic_request_count": request_count}
                    except Exception as e:
                        logger.warning(f"Optimized method failed, falling back to standard method: {str(e)}")
                    
                    # Fall back to the standard method if optimized fails
                    try:
                        request_count = count_carnatic_requests(file_path)
                        if isinstance(request_count, int):
                            logger.info(f"Found {request_count} matching Carnatic GET requests (standard method)")
                            return {"carnatic_request_count": request_count}
                        else:
                            # If there was an error, include the error message
                            results["error"] = f"Failed to count Carnatic requests: {request_count}"
                    except Exception as e:
                        results["error"] = f"Failed to count Carnatic requests using both methods: {str(e)}"
                        
                        # If the file is not too large, include a sample
                        try:
                            file_size = os.path.getsize(file_path)
                            if file_size < 1024 * 1024:  # Less than 1MB
                                if file_ext == '.gz':
                                    with gzip.open(file_path, 'rt', encoding='utf-8', errors='replace') as f:
                                        sample_content = "".join(f.readlines(20))  # Get first 20 lines
                                else:
                                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                                        sample_content = "".join(f.readlines(20))  # Get first 20 lines
                                results[file_name] = {"sample_content": sample_content}
                        except Exception as e:
                            logger.warning(f"Could not read sample content: {str(e)}")
        
        # Check for Telugu bandwidth analysis question
        elif ("telugump3" in question.lower() and 
              ("bandwidth" in question.lower() or "bytes" in question.lower()) and
              "2024-05-31" in question):
            logger.info("Detected Telugu bandwidth analysis question")
            
            # Look for Apache log file (.log or .gz extension)
            for file_path in file_paths:
                file_name = os.path.basename(file_path)
                file_ext = os.path.splitext(file_name)[1].lower()
                
                if file_ext == '.gz' and ('anand' in file_name.lower() or 'may' in file_name.lower()):
                    logger.info(f"Found potential log file: {file_name}")
                    
                    # Run the specialized telugu bandwidth analysis
                    try:
                        top_ip_result = analyze_telugu_bandwidth(file_path)
                        if top_ip_result and len(top_ip_result) == 2:
                            top_ip, total_bytes = top_ip_result
                            logger.info(f"Top IP {top_ip} downloaded {total_bytes} bytes")
                            return {"telugu_bandwidth_bytes": total_bytes}
                        else:
                            results["error"] = f"Failed to analyze telugu bandwidth: Invalid result format"
                    except Exception as e:
                        logger.error(f"Error in Telugu bandwidth analysis: {str(e)}")
                        results["error"] = f"Failed to analyze telugu bandwidth: {str(e)}"
        
        # Check for student ID deduplication question
        elif "student" in question.lower() and (
            ("unique" in question.lower() and "ID" in question) or 
            ("how many" in question.lower() and "student" in question.lower())
        ):
            logger.info("Detected student ID deduplication question")
            
            # Look for the text file
            for file_path in file_paths:
                file_name = os.path.basename(file_path)
                file_ext = os.path.splitext(file_name)[1].lower()
                
                if file_ext == '.txt' and ('student' in file_name.lower() or 'marks' in file_name.lower()):
                    # Count unique student IDs directly
                    unique_count = count_unique_student_ids(file_path)
                    
                    # Return the count directly
                    if isinstance(unique_count, int):
                        logger.info(f"Found {unique_count} unique student IDs")
                        return {"unique_student_ids_count": unique_count}
                    else:
                        # If there was an error, include the error message
                        results["error"] = f"Failed to count unique student IDs: {unique_count}"
                        # Include a sample of the file content for backup
                        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                            sample_content = "".join(f.readlines(100))  # Get first 100 lines
                        results[file_name] = {"sample_content": sample_content}
        
        # Standard processing for all other cases
        for file_path in file_paths:
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1].lower()
            
            # Process based on file extension
            if file_ext == '.zip':
                zip_results = process_zip_file(file_path, question)
                results[file_name] = zip_results
            elif file_ext == '.csv':
                csv_results = process_csv_file(file_path)
                results[file_name] = csv_results
            elif file_ext in ['.xlsx', '.xls']:
                excel_results = process_excel_file(file_path)
                results[file_name] = excel_results
            elif file_ext == '.txt':
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                results[file_name] = {"content": content}
            elif file_ext == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = json.load(f)
                results[file_name] = content
            else:
                results[file_name] = {"error": "Unsupported file format"}
        
        return results
    
    except Exception as e:
        logger.error(f"Error processing files: {str(e)}")
        return {"error": str(e)}

def process_zip_file(zip_path, question):
    """
    Extract and process contents of a ZIP file
    
    Args:
        zip_path (str): Path to the ZIP file
        question (str): The question to guide processing
        
    Returns:
        dict: Data extracted from ZIP contents
    """
    results = {"files": {}}
    extraction_dir = tempfile.mkdtemp()
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extraction_dir)
            
            # Check for specific files mentioned in the question
            csv_pattern = re.compile(r'extract\.csv|data\.csv', re.IGNORECASE)
            
            # Process extracted files
            for root, _, files in os.walk(extraction_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_name = os.path.basename(file_path)
                    file_ext = os.path.splitext(file_name)[1].lower()
                    
                    # Process based on file extension
                    if file_ext == '.csv':
                        try:
                            results["files"][file_name] = process_csv_file(file_path)
                            # If this matches the file mentioned in the question, elevate it
                            if csv_pattern.search(file_name):
                                results["main_csv"] = results["files"][file_name]
                        except Exception as e:
                            results["files"][file_name] = {"error": f"Error processing CSV: {str(e)}"}
                    
                    elif file_ext in ['.xlsx', '.xls']:
                        try:
                            results["files"][file_name] = process_excel_file(file_path)
                        except Exception as e:
                            results["files"][file_name] = {"error": f"Error processing Excel: {str(e)}"}
                    
                    elif file_ext == '.txt':
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                                content = f.read()
                            results["files"][file_name] = {"content": content}
                        except Exception as e:
                            results["files"][file_name] = {"error": f"Error processing text file: {str(e)}"}
                    
                    elif file_ext == '.json':
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = json.load(f)
                            results["files"][file_name] = content
                        except Exception as e:
                            results["files"][file_name] = {"error": f"Error processing JSON: {str(e)}"}
        
        return results
    
    except Exception as e:
        logger.error(f"Error extracting ZIP: {str(e)}")
        return {"error": f"Failed to extract ZIP file: {str(e)}"}
    
    finally:
        # Clean up temporary directory
        try:
            shutil.rmtree(extraction_dir)
        except Exception as cleanup_error:
            logger.error(f"Error cleaning up temporary files: {str(cleanup_error)}")

def process_csv_file(csv_path):
    """
    Process a CSV file and extract data
    
    Args:
        csv_path (str): Path to the CSV file
        
    Returns:
        dict: Data extracted from the CSV
    """
    try:
        df = pd.read_csv(csv_path)
        
        # Check if the CSV has specific columns of interest
        columns = list(df.columns)
        
        # Check for 'answer' column specifically mentioned in the example
        if 'answer' in df.columns:
            answer_values = df['answer'].tolist()
            
            # Return more focused data if answer column exists
            return {
                "columns": columns,
                "rows": len(df),
                "answer_column": answer_values,
                "first_10_rows": df.head(10).to_dict(orient='records'),
                "sample": df.sample(min(5, len(df))).to_dict(orient='records')
            }
        
        # General case
        return {
            "columns": columns,
            "rows": len(df),
            "first_10_rows": df.head(10).to_dict(orient='records'),
            "sample": df.sample(min(5, len(df))).to_dict(orient='records')
        }
    
    except Exception as e:
        logger.error(f"Error processing CSV file: {str(e)}")
        return {"error": f"Failed to process CSV file: {str(e)}"}

def process_excel_file(excel_path):
    """
    Process an Excel file and extract data
    
    Args:
        excel_path (str): Path to the Excel file
        
    Returns:
        dict: Data extracted from the Excel file
    """
    try:
        # Read all sheets
        excel_data = pd.read_excel(excel_path, sheet_name=None)
        result = {"sheets": {}}
        
        for sheet_name, df in excel_data.items():
            columns = list(df.columns)
            
            # Check for 'answer' column
            if 'answer' in df.columns:
                answer_values = df['answer'].tolist()
                
                sheet_data = {
                    "columns": columns,
                    "rows": len(df),
                    "answer_column": answer_values,
                    "first_10_rows": df.head(10).to_dict(orient='records'),
                    "sample": df.sample(min(5, len(df))).to_dict(orient='records')
                }
            else:
                sheet_data = {
                    "columns": columns,
                    "rows": len(df),
                    "first_10_rows": df.head(10).to_dict(orient='records'),
                    "sample": df.sample(min(5, len(df))).to_dict(orient='records')
                }
            
            result["sheets"][sheet_name] = sheet_data
        
        return result
    
    except Exception as e:
        logger.error(f"Error processing Excel file: {str(e)}")
        return {"error": f"Failed to process Excel file: {str(e)}"}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

###############################################
# Flask Routes
###############################################

@app.route('/')
def index():
    """Render the main page with UI for testing the API"""
    return render_template('index.html')

@app.route('/api/', methods=['POST'])
def api():
    """
    API endpoint that accepts:
    - 'question' parameter (required)
    - 'file' attachment (optional)
    
    Returns:
    - JSON with 'answer' field
    """
    try:
        # Check if question is provided
        if 'question' not in request.form:
            return jsonify({"error": "No question provided"}), 400
        
        question = request.form['question']
        logger.debug(f"Received question: {question}")
        
        # Process file if provided
        files = request.files.getlist('file')
        file_data = None
        file_paths = []
        
        if files and files[0].filename:
            try:
                # Create temporary directory for file processing
                temp_dir = tempfile.mkdtemp()
                
                for file in files:
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file_path = os.path.join(temp_dir, filename)
                        file.save(file_path)
                        file_paths.append(file_path)
                        logger.debug(f"Saved file to {file_path}")
                
                # Process files and get relevant data
                if file_paths:
                    file_data = process_files(file_paths, question)
                    
                    # Add file paths to the data dictionary for use in Python code execution
                    if isinstance(file_data, dict):
                        file_data['_file_paths'] = file_paths
            except Exception as e:
                logger.error(f"Error processing file: {str(e)}")
                logger.error(traceback.format_exc())
                return jsonify({"error": f"File processing error: {str(e)}"}), 500
        
        # Get answer from LLM
        answer = answer_question(question, file_data)
        
        return jsonify({"answer": answer})
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
