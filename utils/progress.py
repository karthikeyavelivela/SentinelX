from tqdm import tqdm
import time


class PhaseProgress:
    def __init__(self, title, total):
        self.title = title
        self.total = total
        self.start_time = time.time()

        self.bar = tqdm(
            total=total,
            desc=title,
            ncols=90,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]"
        )

    def update(self):
        self.bar.update(1)

    def close(self):
        self.bar.close()
