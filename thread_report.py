#!/Users/fsalem/bin/python3

import re
from collections import defaultdict
from tabulate import tabulate
import argparse
import itertools

from typing import List, Dict, Tuple, Optional, Union
from matplotlib import pyplot as plt

from cal_mem_report_rss_smaps_shr import memory_info

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
    multi_thread_processes = defaultdict(list)
    for pid, threads in thread_counts.items():
        if len(threads) > 1:
            multi_thread_processes[pid] = {
                'count': len(threads),
                'cmdline': threads[0]['cmdline']
            }

    # Sort processes by thread count
    sorted_multi_thread_processes = sorted(multi_thread_processes.items(),
                                   key=lambda x: x[1]['count'],
                                   reverse=True)

    return {
        'total_threads': kernel_threads + user_threads,
        'kernel_threads': kernel_threads,
        'user_threads': user_threads,
        'sorted_multi_thread_processes': sorted_multi_thread_processes
    }

def generate_report(analysis, top: List[int]):
    """
    Generate a detailed report of thread analysis with tabular output
    """
    print("Thread Analysis Report")
    print("=" * 50)
    print(f"Total Threads: {analysis['total_threads']}")
    print(f"Kernel Threads: {analysis['kernel_threads']}")
    print(f"User Threads: {analysis['user_threads']}")

    # Get default color cycle from Matplotlib for plotting later
    default_colors = plt.rcParams['axes.prop_cycle'].by_key()['color']
    color_cycle = itertools.cycle(default_colors)

    for x in top:
        # Prepare data for tabulation
        table_data = [
            [info['count'], pid, info['cmdline']]
            for pid, info in analysis['sorted_multi_thread_processes'][:x]
        ]

        # Print Top 10 Processes Table
        print(f"\nTop {x} Processes by Thread Count:")
        print(tabulate(table_data,
                    headers=['Thread Count', 'PID', 'Command Line'],
                    tablefmt='grid'))

        labels = [table_data[i][2] for i in range(len(table_data))] + ['other']
        sizes =  [table_data[i][0] for i in range(len(table_data))]

        # add amount of remaining threads to graph in a blob
        sizes.append(analysis['total_threads'] - sum(sizes))

        print("lables: ", labels)
        print("sizes: ", sizes)

        plt.figure(figsize=(16, 12))  # size in inches

        #colors before
        print("colors: ", default_colors)
        # Graph default colors except last set to grey
        # Get Matplotlib's default color cycle and repeat if needed

        # Build color list: assign default colors to all except the last, which is grey
        colors = [next(color_cycle) for _ in range(len(sizes) - 1)] + ['grey']

        # colors after
        print("colors: ", colors)

        # Create pie chart
        plt.pie(sizes,
                labels=labels,
                autopct='%1.1f%%',
                # radius=0.8,
                colors=colors,
                startangle=135,
                labeldistance=1.50,  # move labels out
                pctdistance=0.85,    # position % inside the pie
                counterclock=False,
        )


        plt.axis('equal')  # Equal aspect ratio to make it a circle

        plt.tight_layout()

        # Save to file
        plt.savefig(f'top_{x}_processes_by_thread_count.png')

        plt.close()  # Close the figure to free memory



def main():
    # PS command to get detailed process information
    ps_command = r"ps -w -eo pid,tcnt,stat,sch,pcy,pri,ni,%cpu,c,cpu,vsz,rss,%mem,cmdline"

    # Set up argument parser
    parser = argparse.ArgumentParser(description='Android Thread Analysis')
    parser.add_argument('output_file', type=str, help='Output file to store PS output')

    # Parse arguments
    args = parser.parse_args()

    my_memory_info = memory_info()

    ps_output = my_memory_info.run_adb_shell_command(ps_command)

    if ps_output:
        # Save the PS output to a file
        save_ps_output_to_file(ps_output, args.output_file)

        # Analyze the PS output
        analysis_r = parse_ps_output(ps_output)

        # Generate and print the report
        generate_report(analysis_r, my_memory_info.top)
    else:
        print("Failed to retrieve process information")


if __name__ == "__main__":


    main()
