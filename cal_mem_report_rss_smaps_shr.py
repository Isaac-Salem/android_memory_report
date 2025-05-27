#!/Users/fsalem/bin/python3

import adbutils
import sys
import os
import argparse
import pandas as pd
import re
from typing import List, Dict, Tuple, Optional, Union
import logging
from tabulate import tabulate

import concurrent.futures

# Configure logging at the start of the script
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s: %(message)s',
    filemode = "w",
    filename= 'ps_parsing.log'
)

class memory_info:
    def __init__(self, device_to_connect: Optional[str]=None,
                        output_file: Optional[str]=None,
                        verbose: bool=False,
                        top: Union[List[int], None]=None):

        self.adb = adbutils.AdbClient()
        self.adb_device = self.__get_device(device_to_connect)
        self.output_file = output_file
        self.verbose = verbose
        self.top = self.__parse_top(top)
        self._memory_reporting_metrics = ('rss', 'pss', 'net') # net is RSS - SHR
        self._system_memory_keys = ('total', 'avail', 'free')
        self.system_memory = dict(zip(self._system_memory_keys,
                                    [0] * len(self._system_memory_keys))
                                )


    def __get_device(self, device_serial) -> adbutils.AdbDevice:
        # Set ADB device if specified
        specified_device = None
        if device_serial:
            try:
                print(self.adb.connect(device_serial))
                specified_device = self.adb.device(serial=device_serial)
            except Exception as e:
                print(f"Error connecting to device {device_serial}. Exception: {e}")
                sys.exit(1)
        elif len(self.adb.device_list()) > 1:
            print("Multiple devices connected. Please specify a device with -d.")
            sys.exit(1)
        elif len(self.adb.device_list()) == 0:
            print("No devices connected. Please connect a device first or specify one with -d.")
            sys.exit(1)
        else:
            # otherwise there is only one device connected, so use it
            specified_device = self.adb.device()

        print(f"Using device {specified_device.serial}")
        return specified_device

    def __parse_top(self, top: Union[List[int], List[str], None]) -> List[int]:
        t = [10, 20]
        if isinstance(top[0], str):
            t = [int(x.strip()) for x in top]
        elif isinstance(top[0], int):
            t = top
        else:
            print("Invalid top counts. Using default [10, 20]")

        return t

    def parse_memory_value(self, value: str) -> int:
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


    def run_adb_shell_command(self, command: str) -> str:
        """Run an ADB shell command and return its output."""
        """Enhanced PS output parsing with detailed logging."""
        logger = logging.getLogger(__name__)

        try:
            return self.adb_device.shell(command)
        except Exception as e:
            error_str=f"Error running ADB command: {command},\n Exception: {e}"
            logger.error(error_str)
            return None

    def save_output_to_file(self, content: str, filename: str) -> None:
        """Save content to a file."""
        try:
            with open(filename, 'w') as f:
                f.write(content)
            print(f"\nOutput saved to {filename}")
        except IOError as e:
            print(f"Error saving file {filename}: {e}")

    def calculate_total_avail_free_memory(self) -> Dict[str, int]:
        """Get total memory from /proc/meminfo."""
        # meminfo = run_adb_shell_command("cat /proc/meminfo")
        meminfo = self.adb_device.shell(r"cat /proc/meminfo")
        if meminfo is None:
            print(f"Error in {self.get_total_avail_free.__name__} unable to obtain data from /proc/meminfo")
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
            self.system_memory = dict(zip(self._system_memory_keys,
                                          [total_mem, avail_mem, free_mem]))

    def parse_ps_output(self) -> List[Dict[str, str]]:
        """Enhanced PS output parsing with detailed logging."""
        logger = logging.getLogger(__name__)

        ps_command = r"ps -w -eo pid,stat,sch,pcy,pri,ni,%cpu,c,cpu,vsz,rss,shr,%mem,cmdline"
        ps_output = self.adb_device.shell(ps_command)
        if ps_output is None:
            print(f"Error in {self.parse_ps_output.__name__} unable to obtain data from ps data via adb")
            sys.exit(1)

        # Save PS output to file
        if self.output_file:
            ps_output_filename = f"{self.output_file}.ps.txt"
            self.save_output_to_file(ps_output, ps_output_filename)

        # list of tuples of interest in this format:
        #     2259 0 [jbd2/mmcblk0p22]
        #  Each list item in processes will have this format:
        #     {'pid': '2259', 'rss': 0, 'cmdline': '[jbd2/mmcblk0p22]'}
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
            rss = self.parse_memory_value(row['RSS'])
            shr = self.parse_memory_value(row['SHR'])
            net = rss - shr


            process = {
                'pid': row['PID'],
                'rss': rss,
                'shr': shr,
                'net': net,
                'cmdline': row['CMDLINE']
                }
            processes.append(process)

        return processes

    def get_pss_for_pid(self,pid: str) -> int:
        """Get PSS for a given PID from /proc/PID/smaps."""
        """Enhanced PS output parsing with detailed logging."""
        logger = logging.getLogger(__name__)
        try:
            smaps_output = self.adb_device.shell(f"cat /proc/{pid}/smaps")
            if smaps_output is None:
                error_str = f"Error in {self.get_pss_for_pid.__name__} unable to obtain data from /proc/{pid}/meminfo"
                logger.error(error_str)
                return 0

            # Save smaps output to file if filename is provided
            if self.output_file and self.verbose:
                smaps_output_filename = f"{self.output_file}.{pid}.smaps.txt"
                self.save_output_to_file(smaps_output, smaps_output_filename)

            pss_values = [int(line.split()[1]) for line in smaps_output.split('\n') if line.startswith('Pss:')]
            return sum(pss_values)
        except Exception as e:
            error_str = f"Error in {self.get_pss_for_pid.__name__} unable to obtain data from /proc/{pid}/meminfo"
            logger.error(error_str)
            return 0

    def report_top_processes(self) -> None:
        """Report top processes by memory consumption."""
        processes = self.parse_ps_output()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.top_processes, processes, metric) for metric in self._memory_reporting_metrics]
            for future in concurrent.futures.as_completed(futures):
                future.result()

    def top_processes(self,
                        processes: List[Dict[str,str]],
                        metric: str) -> None:
        """Report top processes by memory consumption for a given metric."""

        if metric not in self._memory_reporting_metrics:
            raise ValueError(f"Invalid metric: {metric}. Valid metrics are: {', '.join(self._memory_reporting_metrics)}")

        # Enrich processes with PSS if needed
        if metric == 'pss':
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = {executor.submit(self.get_pss_for_pid, process['pid']): process for process in processes}
                for future in concurrent.futures.as_completed(futures):
                    process = futures[future]
                    process['pss'] = future.result()
            processes.sort(key=lambda x: x.get('pss', 0), reverse=True)
        else: # net (rss - shr), rss
            processes.sort(key=lambda x: x[metric], reverse=True)

        # Prepare report output
        report_output = []
        prior_top_count = 0
        for top_count in self.top:

            # for the first round of reporting, create the header for the report section
            if prior_top_count == 0:

                report_section = [
                    f"\nTop {top_count} Processes by {metric.upper()}:",
                    f"{'PID':<10}{'Memory (kB)':<15}{'% Total Mem':<15}{'Command'}"
                ]
                report_section.append("-" * 60)

                sum_memory_consumed = 0
            else:
                # leave sum_memory_consumed as it is, since it contains the running total so far
                # remove the last 3 summary lines from the previous report section
                report_section = report_section[:-3]
                # replace the first line of the report with the new top count
                report_section[0] = f"\nTop {top_count} Processes by {metric.upper()}:"

            for proc in processes[prior_top_count:top_count]:
                memory_value = proc.get(metric, 0)
                sum_memory_consumed = sum_memory_consumed + memory_value
                memory_percent = (memory_value / self.system_memory['total']) * 100
                report_section.append(
                    f"{proc['pid']:<10}{memory_value:<15.0f}{memory_percent:<15.2f}{proc['cmdline']}"
                )
            sum_memory_consumed_percent = (sum_memory_consumed / self.system_memory['total']) * 100
            report_section.append("=" * 60)
            report_section.append(f"{'MemStatKB':<10}{sum_memory_consumed:<15.0f}{sum_memory_consumed_percent:<15.2f}")
            report_section.append(f"{'MemStatMB':<10}{sum_memory_consumed/1024:<15.0f}{sum_memory_consumed_percent:<15.2f}")

            # Print to console
            print("\n".join(report_section))

            # Add to report output for potential file saving
            report_output.extend(report_section)
            prior_top_count = top_count

        # Save report to file if filename is provided
        if self.output_file:
            report_filename = f"{self.output_file}.{metric}_report.txt"
            try:
                with open(report_filename, 'w') as f:
                    f.write("\n".join(report_output))
                print(f"\nReport saved to {report_filename}")
            except IOError as e:
                print(f"Error saving report file {report_filename}: {e}")

    def print_mem_stats(self):
        self.calculate_total_avail_free_memory()
        data = [
            ["Total", self.system_memory['total'],
                    self.system_memory['total']/1024,
                    100
            ],
            ["Free", self.system_memory['free'],
                    self.system_memory['free']/1024,
                    self.system_memory['free']/self.system_memory['total'] * 100
            ],
            ["Available", self.system_memory['avail'],
                    self.system_memory['avail']/1024,
                    self.system_memory['avail']/self.system_memory['total'] * 100
            ]
        ]

        headers = ["Memory Type", "KB", "MB", "% of total"]
        print("\nMemory Statistics from /proc/meminfo")

        print(tabulate(data, headers=headers, floatfmt=".2f", tablefmt="github"))

        self.report_top_processes()

def main():
    """Main function to run the script with argument parsing."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Android Device Memory Analysis Tool')

    # Optional arguments
    parser.add_argument('-v', '--verbose',
                        help='Generate smaps file names for each process',
                        action='store_true',
                        default=False)

    parser.add_argument('-o', '--output',
                        help='Base filename for output files',
                        type=str,
                        default=None)

    parser.add_argument('-d', '--device',
                        help='Specify ADB device serial (if multiple devices)',
                        type=str,
                        default=None)

    parser.add_argument('-t', '--top',
                        help='Space separated list of top process counts to report (default: 10 20)',
                        type=int,
                        nargs='*',
                        default=[10,20]) # value used if -t is not used

    # Parse arguments
    args = parser.parse_args()

    my_mem_info = memory_info(device_to_connect=args.device,
                              top=args.top,
                              output_file=args.output,
                              verbose=args.verbose)

    # print memory statistics
    # Perform memory analysis

    my_mem_info.print_mem_stats()


if __name__ == "__main__":
    main()
