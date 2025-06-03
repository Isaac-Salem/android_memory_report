#!/Users/fsalem/bin/python3

import subprocess
import re
from collections import defaultdict
from tabulate import tabulate
import argparse



def run_adb_command(command):
    """
    Run an ADB shell command and return its output
    """
    try:
        full_command = f"adb shell {command}"
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"Error running ADB command: {e}")
        return None

def save_ps_output_to_file(ps_output, filename):
    """
    Save the PS command output to a file
    """
    try:
        with open(filename, 'w') as f:
            f.write(ps_output)
        print(f"PS output saved to {filename}")
    except Exception as e:
        print(f"Error saving output to file: {e}")    

def parse_ps_output(ps_output):
    """
    Parse the PS output and analyze thread counts
    """
    # Split the output into lines and remove the header
    lines = ps_output.split('\n')[1:]
    
    # Data structures to track threads
    thread_counts = defaultdict(list)
    kernel_threads = 0
    user_threads = 0
    
    for line in lines:
        # Split the line into columns
        parts = line.split()
        
        if len(parts) < 14:
            continue
        
        pid = parts[0]
        tcnt = parts[1]
        cmdline = ' '.join(parts[13:])
        
        # Determine if it's a kernel or user thread
        if cmdline.startswith('[') and cmdline.endswith(']'):
            kernel_threads += 1
            thread_type = 'kernel'
        else:
            user_threads += 1
            thread_type = 'user'
        
        # Store thread information
        thread_counts[pid].append({
            'tcnt': tcnt,
            'cmdline': cmdline,
            'type': thread_type
        })
    
    # Process with multiple threads
    multi_thread_processes = {}
    for pid, threads in thread_counts.items():
        if len(threads) > 1:
            multi_thread_processes[pid] = {
                'count': len(threads),
                'cmdline': threads[0]['cmdline']
            }
    
    # Sort processes by thread count
    top_10_processes = sorted(multi_thread_processes.items(), 
                               key=lambda x: x[1]['count'], 
                               reverse=True)[:10]
    
    top_20_processes = sorted(multi_thread_processes.items(), 
                               key=lambda x: x[1]['count'], 
                               reverse=True)[:20]
    
    return {
        'total_threads': kernel_threads + user_threads,
        'kernel_threads': kernel_threads,
        'user_threads': user_threads,
        'top_10_processes': top_10_processes,
        'top_20_processes': top_20_processes
    }

def generate_report(analysis):
    """
    Generate a detailed report of thread analysis with tabular output
    """
    print("Thread Analysis Report")
    print("=" * 50)
    print(f"Total Threads: {analysis['total_threads']}")
    print(f"Kernel Threads: {analysis['kernel_threads']}")
    print(f"User Threads: {analysis['user_threads']}")
    
    # Prepare data for tabulation
    top_10_table_data = [
        [info['count'], pid, info['cmdline']] 
        for pid, info in analysis['top_10_processes']
    ]
    
    top_20_table_data = [
        [info['count'], pid, info['cmdline']] 
        for pid, info in analysis['top_20_processes']
    ]
    
    # Print Top 10 Processes Table
    print("\nTop 10 Processes by Thread Count:")
    print(tabulate.tabulate(top_10_table_data, 
                   headers=['Thread Count', 'PID', 'Command Line'], 
                   tablefmt='grid'))
    
    # Print Top 20 Processes Table
    print("\nTop 20 Processes by Thread Count:")
    print(tabulate.tabulate(top_20_table_data, 
                   headers=['Thread Count', 'PID', 'Command Line'], 
                   tablefmt='grid'))


def main():
    # PS command to get detailed process information
    ps_command = "ps -w -eo pid,tcnt,stat,sch,pcy,pri,ni,%cpu,c,cpu,vsz,rss,%mem,cmdline"

    # Set up argument parser
    parser = argparse.ArgumentParser(description='Android Thread Analysis')
    parser.add_argument('output_file', type=str, help='Output file to store PS output')
    
    # Parse arguments
    args = parser.parse_args()


    # Check ADB connection
    try:
        subprocess.run(['adb', 'devices'], capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError:
        print("ADB not found or no device connected. Please ensure:")
        print("1. ADB is installed")
        print("2. Device is connected")
        print("3. USB debugging is enabled")
        return
    
    # Run the PS command via ADB
    ps_output = run_adb_command(ps_command)
    
    if ps_output:
        # Save the PS output to a file
        save_ps_output_to_file(ps_output, args.output_file)

        # Analyze the PS output
        analysis_r = parse_ps_output(ps_output)
        
        # Generate and print the report
        generate_report(analysis_r)
    else:
        print("Failed to retrieve process information")



    print(f"\nDetailed output saved to {args.output_file}")


if __name__ == "__main__":
    # Check if tabulate is installed, if not, install it
    try:
        import tabulate
    except ImportError:
        print("Tabulate library not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "tabulate"])
        import tabulate

    main()    
