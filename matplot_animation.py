import matplotlib.pyplot as plt
import matplotlib.animation as animation
import random

fig, ax = plt.subplots()
bars = ax.bar(['A', 'B', 'C'], [0, 0, 0])

def update(frame):
    new_values = [random.randint(0, 10) for _ in range(3)]
    for bar, val in zip(bars, new_values):
        bar.set_height(val)
    return bars

ani = animation.FuncAnimation(fig, update, interval=500)
plt.show()
