import math
from collections import defaultdict

class NmapDetector:
    """
    Detector determinista de escaneo de puertos.
    No aprende, no se adapta. Detecta por comportamiento matemático.
    """
    
    def __init__(self, window_seconds=60):
        self.window = window_seconds
        # {src_ip: [(timestamp, dst_port), ...]}
        self._events: dict = defaultdict(list)
    
    def observe(self, src_ip: str, dst_port: int, timestamp: float) -> dict:
        """
        Registra un evento y retorna métricas de comportamiento.
        Retorna score entre 0.0 y 1.0 y flags de detección.
        """
        bucket = self._events[src_ip]
        
        # Limpiar eventos fuera de la ventana
        cutoff = timestamp - self.window
        bucket = [(ts, port) for ts, port in bucket if ts > cutoff]
        bucket.append((timestamp, dst_port))
        self._events[src_ip] = bucket
        
        if len(bucket) < 5:
            return {"score": 0.0, "is_scan": False, "unique_ports": 0, "rate": 0}
        
        ports = [port for _, port in bucket]
        unique_ports = len(set(ports))
        total_events = len(bucket)
        rate_per_min = total_events / (self.window / 60)
        
        # Entropía de puertos — nmap = entropía máxima
        port_entropy = self._entropy(ports)
        max_entropy = math.log2(65535) if unique_ports > 0 else 1.0 # Evitar división por cero
        normalized_entropy = port_entropy / max_entropy
        
        # Score compuesto
        # nmap tiene: muchos puertos únicos + alta tasa + alta entropía
        diversity_ratio = unique_ports / total_events  # nmap ≈ 1.0
        rate_score = min(rate_per_min / 500, 1.0)      # 500/min = score máximo
        
        score = (
            diversity_ratio * 0.5 +
            normalized_entropy * 0.3 +
            rate_score * 0.2
        )
        
        is_scan = (
            unique_ports > 20 and
            diversity_ratio > 0.7 and
            rate_per_min > 50
        )
        
        return {
            "score": round(score, 4),
            "is_scan": is_scan,
            "unique_ports": unique_ports,
            "rate_per_min": round(rate_per_min, 1),
            "diversity_ratio": round(diversity_ratio, 3),
            "port_entropy": round(normalized_entropy, 3),
        }
    
    def _entropy(self, ports: list) -> float:
        if not ports:
            return 0.0
        counts = defaultdict(int)
        for p in ports:
            counts[p] += 1
        total = len(ports)
        return -sum(
            (c / total) * math.log2(c / total)
            for c in counts.values()
            if c > 0
        )
