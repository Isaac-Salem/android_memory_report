#!/Users/fsalem/bin/python3

import subprocess
import sys
import os
import argparse
import pandas as pd
import re
from typing import List, Dict, Tuple
import logging
from tabulate import tabulate

# Configure logging at the start of the script
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s: %(message)s',
    filemode = "w",
    filename= 'ps_parsing.log'
)

def parse_memory_value( value: str) -> int:
    """
    Convert memory values with K or M suffix to kilobytes
    
    :param value: Memory value string
    :return: Memory value in kilobytes
    """
    value = value.strip()
    try:
        if value.endswith('K'):
            return int(float(value[:-1]))
        elif value.endswith('M'):
            return int(float(value[:-1]) * 1024)
        else:
            return int(value)
    except ValueError:
        return 0


def run_adb_shell_command(command: str) -> str:
    """Run an ADB shell command and return its output."""
    """Enhanced PS output parsing with detailed logging."""
    logger = logging.getLogger(__name__)
    
    try:
        result = subprocess.run(['adb', 'shell', command], 
                                capture_output=True, 
                                text=True, 
                                check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        error_str=f"Error running ADB command: {e}"
        logger.error(error_str)
        return None

def save_output_to_file(content: str, filename: str) -> None:
    """Save content to a file."""
    try:
        with open(filename, 'w') as f:
            f.write(content)
        print(f"\nOutput saved to {filename}")
    except IOError as e:
        print(f"Error saving file {filename}: {e}")

def get_total_avail_free_memory():
    """Get total memory from /proc/meminfo."""
    meminfo = run_adb_shell_command("cat /proc/meminfo")
    if meminfo is None:
        print(f"Error in {get_total_avail_free.__name__} unable to obtain data from /proc/meminfo")
        sys.exit(1)

    match1 = re.search(r'MemTotal:\s+(\d+)\s+kB', meminfo)
    if match1:
        total_mem = int(match1.group(1))

    match2 = re.search(r'MemAvailable:\s+(\d+)\s+kB', meminfo)
    if match2:
        avail_mem = int(match2.group(1))

    match3 = re.search(r'MemFree:\s+(\d+)\s+kB', meminfo)
    if match3:
        free_mem = int(match3.group(1))        
    
    if total_mem and avail_mem and free_mem:
        return total_mem, avail_mem, free_mem
    return 0

def parse_ps_output(file_name: str = None) -> List[Dict[str, str]]:
    """Enhanced PS output parsing with detailed logging."""
    logger = logging.getLogger(__name__)
    
    ps_command = "ps -w -eo pid,stat,sch,pcy,pri,ni,%cpu,c,cpu,vsz,rss,shr,%mem,cmdline"
    ps_output = run_adb_shell_command(ps_command)
    if ps_output is None:
        print(f"Error in {parse_ps_output.__name__} unable to obtain data from ps data via adb")
        sys.exit(1)    
    
    # Save PS output to file
    if file_name:
        ps_output_filename = f"{file_name}.ps.txt"
        save_output_to_file(ps_output, ps_output_filename)

    # list of tuples of interest in this format
    #  ===>  2259 0 [jbd2/mmcblk0p22]
    #  Each list item in processes will have this format---->  {'pid': '2259', 'rss': 0, 'cmdline': '[jbd2/mmcblk0p22]'}
    processes = []

    # Create list to store parsed data
    parsed_data = []

    lines = ps_output.strip().split('\n')

    # remove headers
    lines = lines[1:]

    # Parse each line
    for line in lines:
       # Split the line, handling potential spaces in cmdline
        parts = line.split(maxsplit=13)
        
        # Ensure we have all expected columns
        if len(parts) == 14:
            parsed_data.append(parts)

    # Create DataFrame
    df = pd.DataFrame(parsed_data, columns=[
        'PID', 'STAT', 'SCH', 'PCY', 'PRI', 'NI', 
        '%CPU', 'C', 'CPU', 'VSZ', 'RSS', 'SHR', '%MEM', 'CMDLINE'
    ])

    # Convert RSS to numeric, handling potential errors
#    df['RSS'] = pd.to_numeric(df['RSS'], errors='coerce')

    for i in range(len(df)):
        row = df.iloc[i]

        # convert SHR memory values string ending with M and K to a kilobyte integer
        rss = parse_memory_value(row['RSS'])
        shr = parse_memory_value(row['SHR'])
        net = rss - shr

#        print(f"rss {rss} shr_str {shr_str} shr {shr} net {net}")

        process = {
            'pid': row['PID'],
            'rss': rss,
            'shr': shr,
            'net': net,
            'cmdline': row['CMDLINE']
            }
        processes.append(process)
#    exit()

    return processes

def get_pss_for_pid(pid: str, file_name: str = None, verbose: str = None ) -> int:
    """Get PSS for a given PID from /proc/PID/smaps."""
    """Enhanced PS output parsing with detailed logging."""
    logger = logging.getLogger(__name__)    
    try:
        smaps_output = run_adb_shell_command(f"cat /proc/{pid}/smaps")
        if smaps_output is None:
            error_str = f"Error in {get_pss_for_pid.__name__} unable to obtain data from /proc/{pid}/meminfo"
            logger.error(error_str)
            return 0
        
        # Save smaps output to file if filename is provided
        if file_name and verbose:
            smaps_output_filename = f"{file_name}.{pid}.smaps.txt"
            save_output_to_file(smaps_output, smaps_output_filename)
        
        pss_values = [int(line.split()[1]) for line in smaps_output.split('\n') if line.startswith('Pss:')]
        return sum(pss_values)
    except Exception as e:
        error_str = f"Error in {get_pss_for_pid.__name__} unable to obtain data from /proc/{pid}/meminfo"
        logger.error(error_str)
        return 0


def report_top_processes(processes: List[Dict[str,str]], 
                         total_memory: int, 
                         metric: str = 'rss', 
                         top_counts: List[int] = [10, 20],
                         file_name: str = None,
                         verbose: str = None) -> None:
    """Report top processes by memory consumption."""


    # Enrich processes with PSS if needed
    if metric == 'pss':
        for process in processes:
            process['pss'] = get_pss_for_pid(process['pid'], file_name, verbose)
        processes.sort(key=lambda x: x.get('pss', 0), reverse=True)
    if metric == 'rss':  
        processes.sort(key=lambda x: x['rss'], reverse=True)
    if metric == 'net':
        processes.sort(key=lambda x: x['net'], reverse=True)
        

#    print(metric)

#   for process in processes:
#        print(process)


    # Prepare report output
    report_output = []
    for top_count in top_counts:
        report_section = [
            f"\nTop {top_count} Processes by {metric.upper()}:",
            f"{'PID':<10}{'Memory (kB)':<15}{'% Total Mem':<15}{'Command'}"
        ]
        report_section.append("-" * 60)

        sum_memory_consumed = 0
        
        for proc in processes[:top_count]:
            memory_value = proc.get(metric, 0)
            sum_memory_consumed = sum_memory_consumed + memory_value
            memory_percent = (memory_value / total_memory) * 100
            report_section.append(
                f"{proc['pid']:<10}{memory_value:<15.0f}{memory_percent:<15.2f}{proc['cmdline']}"
            )
        sum_memory_consumed_percent = (sum_memory_consumed / total_memory) * 100
        report_section.append("=" * 60)
        report_section.append(f"{"MemStatKB":<10}{sum_memory_consumed:<15.0f}{sum_memory_consumed_percent:<15.2f}")
        report_section.append(f"{"MemStatMB":<10}{sum_memory_consumed/1024:<15.0f}{sum_memory_consumed_percent:<15.2f}")        
        
        
        
        # Print to console
        print("\n".join(report_section))
        
        # Add to report output for potential file saving
        report_output.extend(report_section)
    
    # Save report to file if filename is provided
    if file_name:
        report_filename = f"{file_name}.{metric}_report.txt"
        try:
            with open(report_filename, 'w') as f:
                f.write("\n".join(report_output))
            print(f"\nReport saved to {report_filename}")
        except IOError as e:
            print(f"Error saving report file {report_filename}: {e}")

def main():
    """Main function to run the script with argument parsing."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Android Device Memory Analysis Tool')
    
    # Optional arguments
    parser.add_argument('-v', '--verbose', 
                        help='Generate smaps file names for each process', 
                        type=str, 
                        default=None)    
    parser.add_argument('-o', '--output', 
                        help='Base filename for output files', 
                        type=str, 
                        default=None)
    
    parser.add_argument('-d', '--device', 
                        help='Specify ADB device serial (if multiple devices)', 
                        type=str, 
                        default=None)
    
    parser.add_argument('-t', '--top', 
                        help='Comma-separated list of top process counts to report (default: 10,20)', 
                        type=str, 
                        default='10,20')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Process top counts
    try:
        top_counts = [int(x.strip()) for x in args.top.split(',')]
    except ValueError:
        print("Invalid top counts. Using default [10, 20]")
        top_counts = [10, 20]
    
    # Set ADB device if specified
    if args.device:
        try:
            subprocess.run(['adb', '-s', args.device, 'devices'], check=True)
        except subprocess.CalledProcessError:
            print(f"Error connecting to device {args.device}")
            sys.exit(1)
            


    
    # Perform memory analysis
    total_memory, avail_memory, free_memory = get_total_avail_free_memory()
    data = [
        ["Total", total_memory, total_memory/1024, 100],
        ["Free", free_memory, free_memory/1024, free_memory/total_memory * 100],
        ["Available", avail_memory, avail_memory/1024, avail_memory/total_memory * 100]
        ]

    headers = ["Memory Type", "KB", "MB", "% of total"]
    print("\nMemory Statistics from /proc/meminfo")

    print(tabulate(data, headers=headers, floatfmt=".2f", tablefmt="github"))

#    print(f"{'Memory Type':<20} {'KB':>10} {'MB':>10} {'% of total':>12}")
#    for row in data:
#        print(f"{row[0]:<20} {row[1]:>10} {row[2]:>10.2f} {row[3]:>12.2f}")    



    processes = parse_ps_output(args.output)
    
    # Report using RSS
    report_top_processes(processes, total_memory, 'rss', top_counts, file_name=args.output, verbose=args.verbose)

    # Report using RSS - SHR
    report_top_processes(processes, total_memory, 'net', top_counts, file_name=args.output, verbose=args.verbose)
    
    # Report using PSS
    report_top_processes(processes, total_memory, 'pss', top_counts, file_name=args.output, verbose=args.verbose)

if __name__ == "__main__":
    main()
