import json
import time
import random
import mmh3
import math


def run():
    all_ip_records = read_ip_list_from_file()
    ip_records_count = len(all_ip_records)

    if ip_records_count == 0:
        # probably some error
        return

    print(f"IP records count is {ip_records_count}")

    algorithms = [
        {"name": "Precise calculation (set)", "method": calculate_unique_ips_set},
        {"name": "HyperLogLog", "method": calculate_unique_ips_hyper_log_log},
    ]

    for algorithm in algorithms:
        unique_count, time = execute_and_measure(algorithm["method"], all_ip_records)
        print(f"\nAlgorithm {algorithm["name"]}:")
        print(f"Unique count is {unique_count}, time is {time}")


def execute_and_measure(func, records) -> tuple[int, float]:
    start_time = time.time()
    result = func(records)
    end_time = time.time()
    return result, end_time - start_time


def calculate_unique_ips_set(records: list[str]) -> int:
    records_set = set()

    for record in records:
        records_set.add(record)

    return len(records_set)


def calculate_unique_ips_hyper_log_log(records: list[str]) -> int:
    hll = HyperLogLog(p=10)

    for record in records:
        hll.add(record)

    return hll.count()


def read_ip_list_from_file() -> list[str]:
    file_path = "./lms-stage-access.log"

    result = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                log_record = json.loads(line.strip())
                result.append(log_record["remote_addr"])
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return result


class HyperLogLog:
    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0**-r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


if __name__ == "__main__":
    run()
