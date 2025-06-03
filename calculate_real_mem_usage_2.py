#! /Users/fsalem/bin/python3

import shutil
import subprocess
import re
from typing import List, Dict
from operator import itemgetter

class ADBMemoryAnalyzer:

    proc_meminfo_MemTotal = 0
    
    def __init__(self, device_id: str = None, save_output: bool = True):
        """
        Initialize ADB Memory Analyzer
    
        :param device_id: Optional specific device ID for ADB connection
        :param save_output: Whether to save PS command output to a file
        """
        self.device_id = device_id
        self.save_output = save_output
        self.validate_adb_connection()        

    def validate_adb_connection(self):
        """
        Validate ADB connection and detect available devices
        """
        try:
            # Get list of connected devices
            devices_output = subprocess.check_output(['adb', 'devices'], 
                                                     universal_newlines=True)
            devices = [line.split()[0] for line in devices_output.strip().split('\n')[1:] 
                       if line.strip() and 'device' in line]
            
            # If no device specified, use first available device
            if not self.device_id:
                if not devices:
                    raise RuntimeError("No ADB devices connected")
                self.device_id = devices[0]
            
            # Verify specific device is connected
            if self.device_id not in devices:
                raise RuntimeError(f"Device {self.device_id} not connected")
            
            print(f"Connected to device: {self.device_id}")
        
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"ADB device detection failed: {e}")

    def execute_ps_command(self) -> str:
        """
        Execute PS command via ADB
        
        :return: PS command output as string
        """
        try:
            # Construct ADB command with optional device ID
            adb_command = ['adb']
            if self.device_id:
                adb_command.extend(['-s', self.device_id])
            
            # Full PS command
            ps_command = ['shell', 'ps', '-w', '-eo', 
                          'pid,stat,sch,pri,ni,%cpu,c,cpu,vsz,rss,shr,%mem,cmdline']
            
            full_command = adb_command + ps_command
            
            # Execute command and capture output
            ps_output = subprocess.check_output(full_command, 
                                                universal_newlines=True)
            return ps_output
        
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"PS command execution failed: {e}")

    def parse_memory_value(self, value: str) -> int:
        """
        Convert memory values with K or M suffix to kilobytes
        
        :param value: Memory value string
        :return: Memory value in kilobytes
        """
        value = value.strip()
        try:
            if value.endswith('K'):
                return int(value[:-1])
            elif value.endswith('M'):
                return int(float(value[:-1]) * 1024)
            else:
                return int(value)
        except ValueError:
            return 0

    def process_ps_output(self, ps_output: str) -> List[Dict]:
        """
        Process the PS command output and parse each line
        
        :param ps_output: Raw PS command output
        :return: List of processed process dictionaries
        """
        lines = ps_output.strip().split('\n')
        headers = lines[0].split()
        processes = []

        for line in lines[1:]:
            parts = line.split(None, len(headers)-1)
            if len(parts) == len(headers):
                process = dict(zip(headers, parts))
                
                try:
                    # Convert memory values
                    process['SHR'] = self.parse_memory_value(process['SHR'])
                    process['RSS'] = int(process['RSS'])
                    process['Unique_Memory'] = max(0, process['RSS'] - process['SHR'])
                    
                    processes.append(process)
                except (ValueError, KeyError) as e:
                    print(f"Skipping process due to parsing error: {e}")
                    print(f"Problematic Line: {line}")
                    print(f"Parsed Parts: {parts}")
                    print(f"Headers: {headers}")
                    print("-" * 50)
                    # Print traceback with line number
                    exc_type, exc_value, exc_tb = sys.exc_info()
                    tb = traceback.extract_tb(exc_tb)
    
                    # Print the last entry in the traceback (deepest call)
                    filename, lineno, func, text = tb[-1]
                    print(f"Error in file: {filename}")
                    print(f"Line number: {lineno}")
                    print(f"Function: {func}")
                    print(f"Code: {text}")                    
        
        return processes

    def generate_memory_report(self, processes: List[Dict]):
        """
        Generate comprehensive memory usage report with totals
        
        :param processes: List of processed processes
        """
        # Sort processes by unique memory usage
        sorted_processes = sorted(processes, key=lambda p: p['Unique_Memory'], reverse=True)
    
        # Calculate total memory
        total_unique_memory_kb = sum(p['Unique_Memory'] for p in processes)
        total_unique_memory_mb = total_unique_memory_kb / 1024
        total_rss_memory_kb = sum(p['RSS'] for p in processes)
        total_rss_memory_mb = total_rss_memory_kb / 1024
    
        # Reporting methods
        report_sections = [
            ("Top 10 Memory Consuming Processes", 10),
            ("Top 20 Memory Consuming Processes", 20)
        ]
    
        # Print overall memory summary
        print("\n" + "=" * 50)
        print("ADB Device Memory Analysis Report")
        print("=" * 50)
        
        print(f"\nTotal Memory Usage:")
        print(f"Total Unique Memory: {total_unique_memory_kb:,.0f} KB ({total_unique_memory_mb:,.2f} MB)")
        print(f"Total RSS Memory:    {total_rss_memory_kb:,.0f} KB ({total_rss_memory_mb:,.2f} MB)")
    
        # Generate detailed process reports
        for title, top_n in report_sections:
            print(f"\n{title}:")
            print("{:<10} {:<50} {:<12} {:<15}".format(
                "PID", "Command", "RSS (KB)", "Unique Memory (KB)"
            ))
            print("-" * 90)
            
            # Track section totals
            section_unique_memory_kb = 0
            section_rss_memory_kb = 0
            
            # Display top processes
            for process in sorted_processes[:top_n]:
                print("{:<10} {:<50} {:<12} {:<15}".format(
                    process['PID'], 
                    process['CMDLINE'][:50], 
                    process['RSS'], 
                    process['Unique_Memory']
                ))
                
                # Accumulate section totals
                section_unique_memory_kb += process['Unique_Memory']
                section_rss_memory_kb += process['RSS']
            
            # Print section totals
            print("-" * 90)
            print("{:<62} {:<12} {:<15}".format(
                "Section Totals:", 
                f"{section_rss_memory_kb:,.0f}", 
                f"{section_unique_memory_kb:,.0f}"
            ))
            
            # Calculate and print section percentages
            section_unique_percent = (section_unique_memory_kb / total_unique_memory_kb) * 100
            section_rss_percent = (section_rss_memory_kb / total_rss_memory_kb) * 100
            
            print("{:<62} {:<12.2f} {:<15.2f}".format(
                "Percentage of Total Memory:", 
                section_rss_percent, 
                section_unique_percent
            ))

        # Optional: Detailed memory distribution visualization
        self._visualize_memory_distribution(processes, total_unique_memory_kb)
    
    def _visualize_memory_distribution(self, processes: List[Dict], total_unique_memory_kb: float ):
        """
        Create a simple text-based memory distribution visualization
        
        :param sorted_processes: Sorted list of processes
        :param total_unique_memory_kb: Total unique memory in kilobytes
        """

        MemTotal = self.proc_meminfo_MemTotal
        try:

            # Get terminal width
            terminal_width = shutil.get_terminal_size().columns
            bar_width = min(50, terminal_width - 30)
    
            print("\nMemory Distribution Visualization of Unique Memory (RSS - SHR)as a function to total Unique Memory:")
            print("-" * 90)

            # Sort processes by unique memory usage
            sorted_processes = sorted(processes, key=lambda p: p['Unique_Memory'], reverse=True)            
    
            # Top 20 processes visualization
            for i, process in enumerate(sorted_processes[:20], 1):
                # Calculate percentage and bar length
                percent = (process['Unique_Memory'] / total_unique_memory_kb) * 100
                bar_length = int((percent / 100) * bar_width)
    
                # Create bar
                bar = '█' * bar_length
                
                print(f"{i:2d}. {process['CMDLINE'][:30]:30} {percent:6.2f}% {bar}")

            print("\nMemory Distribution Visualization of RSS function to total System Memory (MemTotal):")
            print("-" * 85)
    
            # Top 20 processes visualization
            ######### debug
            # print(f"MemTotal   ", self.proc_meminfo_MemTotal, " KB\n")

            # Sort processes by RSS usage
            sorted_processes = sorted(processes, key=lambda p: p['RSS'], reverse=True)    

            for i, process in enumerate(sorted_processes[:20], 1):
                # Calculate percentage and bar length
                percent = (process['RSS'] / self.proc_meminfo_MemTotal) * 100
                bar_length = int((percent / 100) * bar_width)
    
                # Create bar
                bar = '█' * bar_length
                
                print(f"{i:2d}. {process['CMDLINE'][:30]:30} {percent:6.2f}% {bar}")                
    
        except Exception as e:
            print(f"Memory distribution visualization failed: {e}")
            # Print traceback with line number
            exc_type, exc_value, exc_tb = sys.exc_info()
            tb = traceback.extract_tb(exc_tb)
    
            # Print the last entry in the traceback (deepest call)
            filename, lineno, func, text = tb[-1]
            print(f"Error in file: {filename}")
            print(f"Line number: {lineno}")
            print(f"Function: {func}")
            print(f"Code: {text}")            

        
    # Modify the run_analysis method to include file saving
    def save_ps_output(self, ps_output: str, filename: str = 'ps.mem_shr.txt'):
        """
        Save PS command output to a file
        
        :param ps_output: Raw PS command output
        :param filename: Name of the file to save (default: ps.mem_shr.txt)
        """
        try:
            # Get current timestamp
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Prepare file content with timestamp
            file_content = f"# PS Command Output - {timestamp}\n"
            file_content += f"# Device: {self.device_id or 'Default'}\n\n"
            file_content += ps_output
            
            # Write to file
            with open(filename, 'w') as f:
                f.write(file_content)
            
            print(f"PS command output saved to {filename}")
        
        except IOError as e:
            print(f"Error saving PS output to file: {e}")
    
    def run_analysis(self):
        """
        Execute full memory analysis workflow
        """
        try:
            # Execute PS command
            ps_output = self.execute_ps_command()
            
            # Conditionally save PS output to file
            if self.save_output:
                self.save_ps_output(ps_output)
            
            # Process PS output
            processes = self.process_ps_output(ps_output)
            
            # Generate report
            self.generate_memory_report(processes)
        
        except Exception as e:
            print(f"Analysis failed: {e}")
            # Print traceback with line number
            exc_type, exc_value, exc_tb = sys.exc_info()
            tb = traceback.extract_tb(exc_tb)
    
            # Print the last entry in the traceback (deepest call)
            filename, lineno, func, text = tb[-1]
            print(f"Error in file: {filename}")
            print(f"Line number: {lineno}")
            print(f"Function: {func}")
            print(f"Code: {text}")            

    def get_device_memory_info(self) -> Dict[str, Dict[str, int]]:
        """
        Retrieve and parse device memory information from /proc/meminfo
        
        :return: Dictionary containing memory information in KB and MB
        """
        try:
            # Construct ADB command with optional device ID
            adb_command = ['adb']
            if self.device_id:
                adb_command.extend(['-s', self.device_id])
                
            # Full command to cat /proc/meminfo
            full_command = adb_command + ['shell', 'cat', '/proc/meminfo']
            
            # Execute command and capture output
            meminfo_output = subprocess.check_output(full_command, 
                                                     universal_newlines=True)
            
            # Parse meminfo output
            meminfo = {}
            for line in meminfo_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip().split()[0]  # Take first value (in KB)
                    
                    try:
                        value_kb = int(value)
                        meminfo[key] = {
                            'KB': value_kb,
                            'MB': round(value_kb / 1024, 2)
                        }
                    except ValueError:
                        print(f"Could not parse value for {key}: {value}")
                        
            return meminfo
        
        except subprocess.CalledProcessError as e:
            print(f"Error retrieving meminfo: {e}")
            return {}
    
    def report_device_memory(self):
        """
        Generate a comprehensive memory information report
        """
        try:
            # Get memory information
            meminfo = self.get_device_memory_info()
            
            # Check for critical memory fields
            critical_fields = ['MemTotal', 'MemAvailable']

            #set the global variable for total system memory
            self.proc_meminfo_MemTotal = meminfo['MemTotal']['KB']

            #debug pring MemTotal
            print(f"MemTotal   ", self.proc_meminfo_MemTotal)
            
            # Print memory report
            print("\n" + "=" * 50)
            print("Device Memory Information based on /proc/meminfo")
            print("=" * 50)
            
            # Report specific fields
            for field in critical_fields:
                if field in meminfo:
                    print(f"\n{field}:")
                    print(f"  Kilobytes (KB): {meminfo[field]['KB']:,}")
                    print(f"  Megabytes (MB): {meminfo[field]['MB']:,.2f}")
                    
            # Calculate and report memory usage
            if 'MemTotal' in meminfo and 'MemAvailable' in meminfo:
                total_kb = meminfo['MemTotal']['KB']
                available_kb = meminfo['MemAvailable']['KB']
                used_kb = total_kb - available_kb
                
                print("\nMemory Usage:")
                print(f"  Used Memory (KB): {used_kb:,}")
                print(f"  Used Memory (MB): {used_kb/1024:,.2f}")
                
                # Calculate percentage
                used_percentage = (used_kb / total_kb) * 100
                print(f"  Memory Usage: {used_percentage:.2f}%")

            print("=" * 50)
                
        except Exception as e:
            print(f"Error generating memory report: {e}")
    
    # Optional: Add method to run both memory analysis and memory info report
    def comprehensive_memory_analysis(self):
        """
        Perform comprehensive memory analysis including process and system memory info
        """
        try:
            # Run process memory analysis
            ps_output = self.execute_ps_command()
            
            # Conditionally save PS output to file
            if self.save_output:
                self.save_ps_output(ps_output)

            # Generate system memory report
            print("\n")  # Add some spacing
            self.report_device_memory()
                
                
            # Process PS output
            processes = self.process_ps_output(ps_output)
            
            # Generate process memory report
            self.generate_memory_report(processes)
            
            
        except Exception as e:
            print(f"Comprehensive analysis failed: {e}")
            # Print traceback with line number
            exc_type, exc_value, exc_tb = sys.exc_info()
            tb = traceback.extract_tb(exc_tb)
            
            # Print the last entry in the traceback (deepest call)
            filename, lineno, func, text = tb[-1]
            print(f"Error in file: {filename}")
            print(f"Line number: {lineno}")
            print(f"Function: {func}")
            print(f"Code: {text}")            
    
def main():
    import sys
    import argparse

    # Create argument parser for more flexible command-line interface
    parser = argparse.ArgumentParser(
        description='ADB Memory Analyzer - Comprehensive Android Device Memory Analysis',
        epilog='Example usages:\n'
               '  python script.py                     # Default analysis\n'
               '  python script.py -                   # No specific device\n'
               '  python script.py device_serial       # Specific device\n'
               '  python script.py -m meminfo          # Memory info only\n'
               '  python script.py -m full             # Comprehensive analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Optional positional argument for device ID
    parser.add_argument('device_id', 
                        nargs='?', 
                        default=None, 
                        help='ADB device serial number (use "-" for no specific device)')

    # Optional mode argument
    parser.add_argument('-m', '--mode', 
                        choices=['process', 'meminfo', 'full'], 
                        default='process', 
                        help='Analysis mode (default: process)')

    # Verbose output option
    parser.add_argument('-v', '--verbose', 
                        action='store_true', 
                        help='Enable verbose output')

    # Save output option
    parser.add_argument('--save', 
                        action='store_true', 
                        help='Save PS command output to file')

    # Parse arguments
    args = parser.parse_args()

    # Handle device ID, treating "-" as None
    device_id = None if args.device_id == '-' else args.device_id

    try:
        # Create analyzer with flexible options
        analyzer = ADBMemoryAnalyzer(
            device_id=device_id, 
            save_output=args.save
        )

        # Set up logging or verbose mode if requested
        if args.verbose:
            # Implement verbose logging (optional enhancement)
            import logging
            logging.basicConfig(
                level=logging.INFO, 
                format='%(asctime)s - %(levelname)s: %(message)s'
            )

        # Select analysis mode
        if args.mode == 'meminfo':
            analyzer.report_device_memory()
        elif args.mode == 'full':
            analyzer.report_device_memory()            
            analyzer.comprehensive_memory_analysis()
        else:  # default process mode
            analyzer.report_device_memory()            
            analyzer.run_analysis()

    except Exception as e:
        print(f"Analysis initialization error: {e}")
        sys.exit(1)

# Optional: Enhanced error handling and logging
def setup_global_exception_handler():
    """
    Set up a global exception handler for unhandled exceptions
    """
    import traceback
    import logging
    import sys

    def global_exception_handler(exctype, value, tb):
        print("Unhandled Exception:")
        print("Type:", exctype.__name__)
        print("Value:", value)
        print("Traceback:")
        traceback.print_tb(tb)
        
        # Optional: Log to file
        try:
            with open('adb_memory_analyzer_error.log', 'a') as log_file:
                log_file.write(f"\n{datetime.now()}: Unhandled Exception\n")
                traceback.print_exception(exctype, value, tb, file=log_file)
        except IOError:
            print("Could not write to error log file")

    sys.excepthook = global_exception_handler

# Modify script entry point
if __name__ == "__main__":
    # Optional: Set up global exception handling
    setup_global_exception_handler()
    
    main()
