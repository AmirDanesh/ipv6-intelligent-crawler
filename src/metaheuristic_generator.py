"""
Metaheuristic Address Generator Module
تولید آدرس‌های IPv6 با الگوریتم‌های فراابتکاری

الگوریتم‌ها:
- Genetic Algorithm (GA)
- Ant Colony Optimization (ACO)
- Cuckoo Search (CS)
"""

import ipaddress
import random
import logging
import math
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import numpy as np
from abc import ABC, abstractmethod

from .feature_extractor import IPv6FeatureExtractor

logger = logging.getLogger(__name__)


@dataclass
class IPv6Individual:
    """یک آدرس IPv6 به عنوان فرد در الگوریتم‌های تکاملی"""
    nibbles: List[int]  # 32 nibble (هر کدام 0-15)
    fitness: float = 0.0
    generation_method: str = ""
    
    def to_address(self) -> str:
        """تبدیل به رشته آدرس IPv6"""
        try:
            bytes_list = []
            for i in range(0, 32, 2):
                byte_val = (self.nibbles[i] << 4) | self.nibbles[i + 1]
                bytes_list.append(byte_val)
            addr = ipaddress.IPv6Address(bytes(bytes_list))
            return str(addr)
        except:
            return None
    
    @staticmethod
    def from_address(address: str) -> 'IPv6Individual':
        """ایجاد از رشته آدرس IPv6"""
        ip = ipaddress.IPv6Address(address)
        ip_int = int(ip)
        nibbles = []
        for i in range(31, -1, -1):
            nibbles.insert(0, (ip_int >> (i * 4)) & 0xF)
        return IPv6Individual(nibbles=nibbles)
    
    def copy(self) -> 'IPv6Individual':
        return IPv6Individual(
            nibbles=self.nibbles.copy(),
            fitness=self.fitness,
            generation_method=self.generation_method
        )


# =============================================================================
# Genetic Algorithm
# =============================================================================

class GeneticAlgorithmGenerator:
    """
    الگوریتم ژنتیک برای تولید آدرس IPv6
    
    ویژگی‌ها:
    - Crossover: ترکیب دو آدرس فعال
    - Mutation: تغییر تصادفی nibble ها
    - Selection: انتخاب بهترین‌ها بر اساس fitness
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # پارامترهای GA
        self.population_size = self.config.get('population_size', 100)
        self.mutation_rate = self.config.get('mutation_rate', 0.1)
        self.crossover_rate = self.config.get('crossover_rate', 0.8)
        self.elite_size = self.config.get('elite_size', 10)
        self.generations = self.config.get('generations', 50)
        
        # جمعیت فعلی
        self.population: List[IPv6Individual] = []
        self.best_individual: Optional[IPv6Individual] = None
        
        # تابع fitness خارجی (از ML model یا probe نتایج)
        self.fitness_function = None
        
        # آدرس‌های تولید شده
        self.generated: Set[str] = set()
        
    def set_fitness_function(self, func):
        """تنظیم تابع fitness"""
        self.fitness_function = func
        
    def initialize_population(self, seed_addresses: List[str]):
        """مقداردهی اولیه جمعیت از آدرس‌های seed"""
        self.population = []
        
        # اضافه کردن seed ها
        for addr in seed_addresses[:self.population_size // 2]:
            try:
                individual = IPv6Individual.from_address(addr)
                individual.fitness = 1.0  # آدرس‌های فعال شناخته شده
                individual.generation_method = "seed"
                self.population.append(individual)
            except:
                continue
        
        # تکمیل با mutation از seed ها
        while len(self.population) < self.population_size:
            if self.population:
                parent = random.choice(self.population[:len(seed_addresses)])
                child = self._mutate(parent.copy())
                child.generation_method = "initial_mutation"
                self.population.append(child)
            else:
                # اگر seed نداریم، تصادفی تولید کن
                individual = self._random_individual()
                individual.generation_method = "random"
                self.population.append(individual)
                
        logger.info(f"GA initialized with {len(self.population)} individuals")
    
    def _random_individual(self) -> IPv6Individual:
        """تولید فرد تصادفی در محدوده‌های معتبر"""
        # شروع با یک prefix معتبر
        prefixes = [
            [0x2, 0x0, 0x0, 0x1],  # 2001::/16
            [0x2, 0x4],            # 2400::/12
            [0x2, 0x6],            # 2600::/12
            [0x2, 0xa],            # 2a00::/12
        ]
        prefix = random.choice(prefixes)
        nibbles = prefix + [random.randint(0, 15) for _ in range(32 - len(prefix))]
        return IPv6Individual(nibbles=nibbles)
    
    def _crossover(self, parent1: IPv6Individual, parent2: IPv6Individual) -> Tuple[IPv6Individual, IPv6Individual]:
        """
        Crossover دو نقطه‌ای
        حفظ prefix و ترکیب interface ID
        """
        if random.random() > self.crossover_rate:
            return parent1.copy(), parent2.copy()
        
        # نقاط crossover (بعد از prefix، در interface ID)
        point1 = random.randint(16, 24)  # در نیمه دوم آدرس
        point2 = random.randint(point1, 31)
        
        child1_nibbles = (
            parent1.nibbles[:point1] + 
            parent2.nibbles[point1:point2] + 
            parent1.nibbles[point2:]
        )
        child2_nibbles = (
            parent2.nibbles[:point1] + 
            parent1.nibbles[point1:point2] + 
            parent2.nibbles[point2:]
        )
        
        child1 = IPv6Individual(nibbles=child1_nibbles, generation_method="crossover")
        child2 = IPv6Individual(nibbles=child2_nibbles, generation_method="crossover")
        
        return child1, child2
    
    def _mutate(self, individual: IPv6Individual) -> IPv6Individual:
        """Mutation با احتمال متغیر"""
        for i in range(16, 32):  # فقط interface ID رو mutate کن
            if random.random() < self.mutation_rate:
                # انواع مختلف mutation
                mutation_type = random.choice(['random', 'increment', 'decrement', 'swap'])
                
                if mutation_type == 'random':
                    individual.nibbles[i] = random.randint(0, 15)
                elif mutation_type == 'increment':
                    individual.nibbles[i] = (individual.nibbles[i] + 1) % 16
                elif mutation_type == 'decrement':
                    individual.nibbles[i] = (individual.nibbles[i] - 1) % 16
                elif mutation_type == 'swap' and i < 31:
                    individual.nibbles[i], individual.nibbles[i+1] = \
                        individual.nibbles[i+1], individual.nibbles[i]
        
        individual.generation_method = "mutation"
        return individual
    
    def _select_parents(self) -> Tuple[IPv6Individual, IPv6Individual]:
        """Tournament Selection"""
        tournament_size = 5
        
        def tournament():
            candidates = random.sample(self.population, tournament_size)
            return max(candidates, key=lambda x: x.fitness)
        
        return tournament(), tournament()
    
    def _evaluate_population(self):
        """ارزیابی fitness جمعیت"""
        if self.fitness_function is None:
            return
        
        addresses = [ind.to_address() for ind in self.population if ind.to_address()]
        
        # دریافت fitness از تابع خارجی
        fitness_scores = self.fitness_function(addresses)
        
        for ind, score in zip(self.population, fitness_scores):
            ind.fitness = score
    
    def evolve(self) -> List[IPv6Individual]:
        """یک نسل تکامل"""
        # ارزیابی
        self._evaluate_population()
        
        # مرتب‌سازی بر اساس fitness
        self.population.sort(key=lambda x: x.fitness, reverse=True)
        
        # ذخیره بهترین
        if self.population:
            self.best_individual = self.population[0].copy()
        
        # نسل جدید
        new_population = []
        
        # Elitism - حفظ بهترین‌ها
        new_population.extend([ind.copy() for ind in self.population[:self.elite_size]])
        
        # تولید بقیه با crossover و mutation
        while len(new_population) < self.population_size:
            parent1, parent2 = self._select_parents()
            child1, child2 = self._crossover(parent1, parent2)
            
            child1 = self._mutate(child1)
            child2 = self._mutate(child2)
            
            new_population.extend([child1, child2])
        
        self.population = new_population[:self.population_size]
        return self.population
    
    def generate(self, seed_addresses: List[str], generations: int = None) -> List[str]:
        """تولید آدرس‌های جدید"""
        generations = generations or self.generations
        
        self.initialize_population(seed_addresses)
        
        for gen in range(generations):
            self.evolve()
            logger.debug(f"GA Generation {gen+1}: Best fitness = {self.best_individual.fitness:.4f}")
        
        # برگرداندن آدرس‌های یکتا
        addresses = []
        for ind in self.population:
            addr = ind.to_address()
            if addr and addr not in self.generated:
                self.generated.add(addr)
                addresses.append(addr)
        
        return addresses


# =============================================================================
# Ant Colony Optimization
# =============================================================================

class AntColonyGenerator:
    """
    الگوریتم کلونی مورچگان برای تولید آدرس IPv6
    
    ایده: هر nibble یک گره در گراف است
    مورچه‌ها مسیرهایی (آدرس‌ها) را طی می‌کنند
    فرومون روی مسیرهای موفق بیشتر می‌شود
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # پارامترهای ACO
        self.n_ants = self.config.get('n_ants', 50)
        self.n_iterations = self.config.get('n_iterations', 100)
        self.alpha = self.config.get('alpha', 1.0)      # اهمیت فرومون
        self.beta = self.config.get('beta', 2.0)        # اهمیت heuristic
        self.rho = self.config.get('rho', 0.1)          # نرخ تبخیر
        self.q = self.config.get('q', 100)              # ثابت فرومون
        
        # ماتریس فرومون: [position][from_nibble][to_nibble]
        # 32 موقعیت، هر کدام 16x16 انتقال
        self.pheromone = np.ones((32, 16, 16)) * 0.1
        
        # Heuristic information (از الگوهای یادگرفته شده)
        self.heuristic = np.ones((32, 16, 16))
        
        # آدرس‌های تولید شده
        self.generated: Set[str] = set()
        
        # تابع ارزیابی
        self.fitness_function = None
        
    def set_fitness_function(self, func):
        """تنظیم تابع fitness"""
        self.fitness_function = func
    
    def learn_patterns(self, active_addresses: List[str]):
        """یادگیری الگو از آدرس‌های فعال برای heuristic"""
        logger.info(f"ACO learning from {len(active_addresses)} addresses")
        
        for addr in active_addresses:
            try:
                ind = IPv6Individual.from_address(addr)
                nibbles = ind.nibbles
                
                # افزایش heuristic برای انتقالات دیده شده
                for i in range(31):
                    from_n = nibbles[i]
                    to_n = nibbles[i + 1]
                    self.heuristic[i][from_n][to_n] += 1.0
                    
                # افزایش فرومون اولیه
                for i in range(31):
                    from_n = nibbles[i]
                    to_n = nibbles[i + 1]
                    self.pheromone[i][from_n][to_n] += 0.5
                    
            except Exception as e:
                logger.debug(f"Error learning from {addr}: {e}")
        
        # نرمال‌سازی
        self.heuristic = self.heuristic / (self.heuristic.max() + 1e-10)
        self.heuristic = np.clip(self.heuristic, 0.01, 1.0)
    
    def _construct_solution(self) -> IPv6Individual:
        """ساخت یک آدرس توسط یک مورچه"""
        nibbles = []
        
        # شروع با یک prefix معتبر (اولین 4 nibble)
        prefixes = [
            [0x2, 0x0, 0x0, 0x1],  # 2001
            [0x2, 0x4, 0x0, 0x0],  # 2400
            [0x2, 0x6, 0x0, 0x0],  # 2600
            [0x2, 0xa, 0x0, 0x0],  # 2a00
        ]
        
        # انتخاب احتمالاتی prefix بر اساس فرومون
        prefix_probs = []
        for prefix in prefixes:
            prob = self.pheromone[0][prefix[0]][prefix[1]] if len(prefix) > 1 else 1.0
            prefix_probs.append(prob)
        
        prefix_probs = np.array(prefix_probs)
        prefix_probs = prefix_probs / prefix_probs.sum()
        chosen_prefix = prefixes[np.random.choice(len(prefixes), p=prefix_probs)]
        
        nibbles = chosen_prefix.copy()
        
        # ساخت بقیه آدرس با قانون احتمالاتی ACO
        current_nibble = nibbles[-1]
        
        for pos in range(len(nibbles), 32):
            # محاسبه احتمال برای هر nibble بعدی
            probs = np.zeros(16)
            
            for next_nibble in range(16):
                tau = self.pheromone[pos-1][current_nibble][next_nibble]  # فرومون
                eta = self.heuristic[pos-1][current_nibble][next_nibble]  # heuristic
                probs[next_nibble] = (tau ** self.alpha) * (eta ** self.beta)
            
            # نرمال‌سازی
            probs_sum = probs.sum()
            if probs_sum > 0:
                probs = probs / probs_sum
            else:
                probs = np.ones(16) / 16
            
            # انتخاب nibble بعدی
            next_nibble = np.random.choice(16, p=probs)
            nibbles.append(next_nibble)
            current_nibble = next_nibble
        
        return IPv6Individual(nibbles=nibbles, generation_method="aco")
    
    def _update_pheromone(self, solutions: List[Tuple[IPv6Individual, float]]):
        """به‌روزرسانی فرومون"""
        # تبخیر
        self.pheromone *= (1 - self.rho)
        
        # افزودن فرومون جدید
        for individual, fitness in solutions:
            if fitness > 0:
                nibbles = individual.nibbles
                deposit = self.q * fitness
                
                for i in range(31):
                    from_n = nibbles[i]
                    to_n = nibbles[i + 1]
                    self.pheromone[i][from_n][to_n] += deposit
        
        # محدود کردن مقادیر فرومون
        self.pheromone = np.clip(self.pheromone, 0.01, 10.0)
    
    def generate(self, seed_addresses: List[str], iterations: int = None) -> List[str]:
        """تولید آدرس‌های جدید"""
        iterations = iterations or self.n_iterations
        
        # یادگیری از seed ها
        self.learn_patterns(seed_addresses)
        
        all_addresses = []
        
        for iteration in range(iterations):
            # ساخت راه‌حل‌ها توسط مورچه‌ها
            solutions = []
            for _ in range(self.n_ants):
                individual = self._construct_solution()
                addr = individual.to_address()
                
                if addr and addr not in self.generated:
                    self.generated.add(addr)
                    solutions.append((individual, 0.5))  # fitness اولیه
                    all_addresses.append(addr)
            
            # ارزیابی و به‌روزرسانی فرومون
            if self.fitness_function and solutions:
                addresses = [s[0].to_address() for s in solutions]
                fitness_scores = self.fitness_function(addresses)
                solutions = [(s[0], f) for s, f in zip(solutions, fitness_scores)]
            
            self._update_pheromone(solutions)
            
            if iteration % 10 == 0:
                logger.debug(f"ACO Iteration {iteration}: Generated {len(all_addresses)} addresses")
        
        return all_addresses


# =============================================================================
# Cuckoo Search
# =============================================================================

class CuckooSearchGenerator:
    """
    الگوریتم جستجوی فاخته برای تولید آدرس IPv6
    
    ویژگی‌ها:
    - Lévy Flight برای کاوش گسترده
    - جایگزینی لانه‌های بد
    - تعادل بین کاوش و بهره‌برداری
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # پارامترهای Cuckoo Search
        self.n_nests = self.config.get('n_nests', 50)
        self.pa = self.config.get('pa', 0.25)           # احتمال کشف تخم
        self.alpha = self.config.get('alpha', 0.01)     # اندازه گام
        self.n_iterations = self.config.get('n_iterations', 100)
        
        # لانه‌ها (آدرس‌ها)
        self.nests: List[IPv6Individual] = []
        self.best_nest: Optional[IPv6Individual] = None
        
        # آدرس‌های تولید شده
        self.generated: Set[str] = set()
        
        # تابع ارزیابی
        self.fitness_function = None
    
    def set_fitness_function(self, func):
        """تنظیم تابع fitness"""
        self.fitness_function = func
    
    def initialize_nests(self, seed_addresses: List[str]):
        """مقداردهی اولیه لانه‌ها"""
        self.nests = []
        
        # از seed ها شروع کن
        for addr in seed_addresses[:self.n_nests]:
            try:
                individual = IPv6Individual.from_address(addr)
                individual.fitness = 1.0
                individual.generation_method = "seed"
                self.nests.append(individual)
            except:
                continue
        
        # تکمیل با mutation
        while len(self.nests) < self.n_nests:
            if self.nests:
                parent = random.choice(self.nests)
                child = self._levy_flight(parent.copy())
                child.generation_method = "levy_init"
                self.nests.append(child)
            else:
                self.nests.append(self._random_nest())
        
        logger.info(f"Cuckoo Search initialized with {len(self.nests)} nests")
    
    def _random_nest(self) -> IPv6Individual:
        """ایجاد لانه تصادفی"""
        prefixes = [
            [0x2, 0x0, 0x0, 0x1],
            [0x2, 0x4],
            [0x2, 0x6],
            [0x2, 0xa],
        ]
        prefix = random.choice(prefixes)
        nibbles = prefix + [random.randint(0, 15) for _ in range(32 - len(prefix))]
        return IPv6Individual(nibbles=nibbles, generation_method="random")
    
    def _levy_flight(self, individual: IPv6Individual) -> IPv6Individual:
        """
        Lévy Flight - پرش‌های با توزیع Lévy
        گام‌های بزرگ گاهی اوقات، گام‌های کوچک بیشتر اوقات
        """
        # پارامتر Lévy (معمولاً 1.5)
        beta = 1.5
        
        # محاسبه sigma
        sigma = (
            math.gamma(1 + beta) * math.sin(math.pi * beta / 2) /
            (math.gamma((1 + beta) / 2) * beta * (2 ** ((beta - 1) / 2)))
        ) ** (1 / beta)
        
        new_nibbles = individual.nibbles.copy()
        
        # اعمال Lévy flight به interface ID
        for i in range(16, 32):  # فقط نیمه دوم
            u = np.random.normal(0, sigma)
            v = np.random.normal(0, 1)
            step = u / (abs(v) ** (1 / beta))
            
            # اعمال گام
            change = int(self.alpha * step * 16)
            new_nibbles[i] = (new_nibbles[i] + change) % 16
        
        individual.nibbles = new_nibbles
        individual.generation_method = "levy_flight"
        return individual
    
    def _get_cuckoo(self) -> IPv6Individual:
        """تولید فاخته جدید با Lévy flight"""
        # انتخاب یک لانه تصادفی
        nest = random.choice(self.nests)
        cuckoo = self._levy_flight(nest.copy())
        return cuckoo
    
    def _abandon_worst_nests(self):
        """رها کردن بدترین لانه‌ها"""
        n_abandon = int(self.pa * self.n_nests)
        
        # مرتب‌سازی بر اساس fitness
        self.nests.sort(key=lambda x: x.fitness, reverse=True)
        
        # جایگزینی بدترین‌ها
        for i in range(self.n_nests - n_abandon, self.n_nests):
            # ایجاد لانه جدید با ترکیب دو لانه خوب
            if len(self.nests) >= 2:
                nest1, nest2 = random.sample(self.nests[:self.n_nests // 2], 2)
                new_nibbles = []
                for j in range(32):
                    if random.random() < 0.5:
                        new_nibbles.append(nest1.nibbles[j])
                    else:
                        new_nibbles.append(nest2.nibbles[j])
                self.nests[i] = IPv6Individual(
                    nibbles=new_nibbles,
                    generation_method="abandoned_replace"
                )
            else:
                self.nests[i] = self._random_nest()
    
    def _evaluate_nests(self):
        """ارزیابی fitness لانه‌ها"""
        if self.fitness_function is None:
            return
        
        addresses = [nest.to_address() for nest in self.nests if nest.to_address()]
        fitness_scores = self.fitness_function(addresses)
        
        for nest, score in zip(self.nests, fitness_scores):
            nest.fitness = score
    
    def generate(self, seed_addresses: List[str], iterations: int = None) -> List[str]:
        """تولید آدرس‌های جدید"""
        iterations = iterations or self.n_iterations
        
        self.initialize_nests(seed_addresses)
        
        for iteration in range(iterations):
            # تولید فاخته جدید
            cuckoo = self._get_cuckoo()
            
            # انتخاب یک لانه تصادفی برای مقایسه
            j = random.randint(0, self.n_nests - 1)
            
            # ارزیابی
            if self.fitness_function:
                cuckoo_addr = cuckoo.to_address()
                if cuckoo_addr:
                    cuckoo.fitness = self.fitness_function([cuckoo_addr])[0]
            
            # اگر فاخته بهتر است، جایگزین کن
            if cuckoo.fitness > self.nests[j].fitness:
                self.nests[j] = cuckoo
            
            # رها کردن بدترین لانه‌ها
            self._abandon_worst_nests()
            
            # ارزیابی
            self._evaluate_nests()
            
            # به‌روزرسانی بهترین
            current_best = max(self.nests, key=lambda x: x.fitness)
            if self.best_nest is None or current_best.fitness > self.best_nest.fitness:
                self.best_nest = current_best.copy()
            
            if iteration % 10 == 0:
                logger.debug(f"Cuckoo Iteration {iteration}: Best fitness = {self.best_nest.fitness:.4f}")
        
        # جمع‌آوری آدرس‌های یکتا
        addresses = []
        for nest in self.nests:
            addr = nest.to_address()
            if addr and addr not in self.generated:
                self.generated.add(addr)
                addresses.append(addr)
        
        return addresses


# =============================================================================
# Hybrid Generator - ترکیب همه الگوریتم‌ها
# =============================================================================

class HybridMetaheuristicGenerator:
    """
    ترکیب هوشمند الگوریتم‌های فراابتکاری
    
    استراتژی:
    1. هر الگوریتم مستقل کار می‌کند
    2. نتایج ترکیب می‌شوند
    3. موفقیت هر الگوریتم ردیابی می‌شود
    4. تخصیص منابع بر اساس موفقیت تنظیم می‌شود
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # ایجاد نمونه از هر الگوریتم
        self.ga = GeneticAlgorithmGenerator(config.get('ga', {}))
        self.aco = AntColonyGenerator(config.get('aco', {}))
        self.cs = CuckooSearchGenerator(config.get('cs', {}))
        
        # آمار موفقیت
        self.success_rates = {
            'ga': {'hits': 0, 'total': 0},
            'aco': {'hits': 0, 'total': 0},
            'cs': {'hits': 0, 'total': 0}
        }
        
        # وزن‌های اولیه
        self.weights = {'ga': 0.33, 'aco': 0.33, 'cs': 0.34}
        
        # تابع fitness
        self.fitness_function = None
        
        # آدرس‌های تولید شده
        self.generated: Set[str] = set()
        
    def set_fitness_function(self, func):
        """تنظیم تابع fitness برای همه الگوریتم‌ها"""
        self.fitness_function = func
        self.ga.set_fitness_function(func)
        self.aco.set_fitness_function(func)
        self.cs.set_fitness_function(func)
    
    def generate(
        self,
        seed_addresses: List[str],
        total_count: int = 1000
    ) -> Dict[str, List[str]]:
        """
        تولید آدرس‌ها با تمام الگوریتم‌ها
        
        Returns:
            Dict با کلید نام الگوریتم و مقدار لیست آدرس‌ها
        """
        results = {}
        
        # تخصیص تعداد بر اساس وزن‌ها
        ga_count = int(total_count * self.weights['ga'])
        aco_count = int(total_count * self.weights['aco'])
        cs_count = total_count - ga_count - aco_count
        
        logger.info(f"Generating: GA={ga_count}, ACO={aco_count}, CS={cs_count}")
        
        # تولید با هر الگوریتم
        try:
            ga_generations = max(10, ga_count // self.ga.population_size)
            results['ga'] = self.ga.generate(seed_addresses, ga_generations)[:ga_count]
            logger.info(f"GA generated {len(results['ga'])} addresses")
        except Exception as e:
            logger.error(f"GA error: {e}")
            results['ga'] = []
        
        try:
            aco_iterations = max(10, aco_count // self.aco.n_ants)
            results['aco'] = self.aco.generate(seed_addresses, aco_iterations)[:aco_count]
            logger.info(f"ACO generated {len(results['aco'])} addresses")
        except Exception as e:
            logger.error(f"ACO error: {e}")
            results['aco'] = []
        
        try:
            cs_iterations = max(10, cs_count // self.cs.n_nests)
            results['cs'] = self.cs.generate(seed_addresses, cs_iterations)[:cs_count]
            logger.info(f"CS generated {len(results['cs'])} addresses")
        except Exception as e:
            logger.error(f"CS error: {e}")
            results['cs'] = []
        
        # ذخیره همه آدرس‌ها
        for algo_results in results.values():
            self.generated.update(algo_results)
        
        return results
    
    def update_success(self, algorithm: str, hits: int, total: int):
        """به‌روزرسانی آمار موفقیت یک الگوریتم"""
        if algorithm in self.success_rates:
            self.success_rates[algorithm]['hits'] += hits
            self.success_rates[algorithm]['total'] += total
            
            # به‌روزرسانی وزن‌ها
            self._update_weights()
    
    def _update_weights(self):
        """به‌روزرسانی وزن‌ها بر اساس نرخ موفقیت"""
        rates = {}
        for algo, stats in self.success_rates.items():
            if stats['total'] > 0:
                rates[algo] = stats['hits'] / stats['total']
            else:
                rates[algo] = 0.33
        
        total_rate = sum(rates.values())
        if total_rate > 0:
            for algo in self.weights:
                self.weights[algo] = rates[algo] / total_rate
        
        logger.info(f"Updated weights: {self.weights}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """دریافت آمار"""
        return {
            'total_generated': len(self.generated),
            'weights': self.weights.copy(),
            'success_rates': {
                algo: stats['hits'] / stats['total'] if stats['total'] > 0 else 0
                for algo, stats in self.success_rates.items()
            }
        }


# =============================================================================
# Example Usage
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # آدرس‌های seed نمونه
    seeds = [
        "2001:4860:4860::8888",  # Google DNS
        "2001:4860:4860::8844",  # Google DNS
        "2606:4700:4700::1111",  # Cloudflare
        "2606:4700:4700::1001",  # Cloudflare
        "2620:fe::fe",           # Quad9
    ]
    
    # تست هر الگوریتم
    print("=" * 60)
    print("Testing Genetic Algorithm")
    print("=" * 60)
    ga = GeneticAlgorithmGenerator({'population_size': 20, 'generations': 10})
    ga_results = ga.generate(seeds, generations=10)
    print(f"Generated {len(ga_results)} addresses")
    for addr in ga_results[:5]:
        print(f"  {addr}")
    
    print("\n" + "=" * 60)
    print("Testing Ant Colony Optimization")
    print("=" * 60)
    aco = AntColonyGenerator({'n_ants': 10, 'n_iterations': 20})
    aco_results = aco.generate(seeds, iterations=20)
    print(f"Generated {len(aco_results)} addresses")
    for addr in aco_results[:5]:
        print(f"  {addr}")
    
    print("\n" + "=" * 60)
    print("Testing Cuckoo Search")
    print("=" * 60)
    cs = CuckooSearchGenerator({'n_nests': 20, 'n_iterations': 20})
    cs_results = cs.generate(seeds, iterations=20)
    print(f"Generated {len(cs_results)} addresses")
    for addr in cs_results[:5]:
        print(f"  {addr}")
    
    print("\n" + "=" * 60)
    print("Testing Hybrid Generator")
    print("=" * 60)
    hybrid = HybridMetaheuristicGenerator()
    hybrid_results = hybrid.generate(seeds, total_count=100)
    print(f"Statistics: {hybrid.get_statistics()}")
