import random
from datetime import datetime
import tkinter as tk
from tkinter import Canvas, Frame, Scrollbar, filedialog, messagebox
import csv
import numpy as np

class AnomalyDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Access Anomaly Detection")
        self.root.geometry("900x700")

        # Variables to store data
        self.logs = None
        self.features = None
        self.anomalies = None
        self.private_anomalies = None
        self.clusters = None
        self.file_path = None
        self.n_clusters = 2  

    #GUI
        self.setup_gui()

    def setup_gui(self):
        
        self.canvas = Canvas(self.root, width=500, height=400, bg="white")
        self.canvas.pack(pady=20)

        self.result_frame = Frame(self.root)
        self.result_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        self.scrollbar = Scrollbar(self.result_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_widget = tk.Text(self.result_frame, height=10, width=50, font=("Arial", 12), wrap=tk.WORD)
        self.text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.text_widget.config(state=tk.DISABLED)
        self.scrollbar.config(command=self.text_widget.yview)
        self.text_widget.config(yscrollcommand=self.scrollbar.set)

        self.upload_frame = Frame(self.root)
        self.upload_frame.pack(pady=10)

        self.upload_button = tk.Button(self.upload_frame, text="Upload Log File", command=self.upload_file)
        self.upload_button.pack(side=tk.LEFT, padx=5)

        self.file_label = tk.Label(self.upload_frame, text="No file selected", font=("Arial", 12))
        self.file_label.pack(side=tk.LEFT, padx=5)

        self.process_button = tk.Button(self.upload_frame, text="Process File", command=self.process_file, state=tk.DISABLED)
        self.process_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = tk.Button(self.upload_frame, text="Clear", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.clusters_var = tk.StringVar(self.root)
        self.clusters_var.set(str(self.n_clusters))
        self.clusters_var.trace("w", self.update_n_clusters)
        clusters_options = [str(i) for i in range(2, 10)]
        self.clusters_dropdown = tk.OptionMenu(self.upload_frame, self.clusters_var, *clusters_options)
        self.clusters_dropdown.pack(side=tk.LEFT, padx=5)

        self.clusters_label = tk.Label(self.upload_frame, text="Number of Clusters:", font=("Arial", 12))
        self.clusters_label.pack(side=tk.LEFT, padx=5)

        self.status_label = tk.Label(self.root, text="", font=("Arial", 12))
        self.status_label.pack(pady=5)

    def update_n_clusters(self, *args):
        self.n_clusters = int(self.clusters_var.get())

    def upload_file(self):
        
        self.file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if self.file_path:
            self.file_label.config(text=self.file_path.split('/')[-1])
            self.process_button.config(state=tk.NORMAL)
        else:
            self.file_label.config(text="No file selected")
            self.process_button.config(state=tk.DISABLED)

    def clear_results(self):
    
        self.file_path = None
        self.logs = None
        self.features = None
        self.anomalies = None
        self.private_anomalies = None
        self.clusters = None

        self.file_label.config(text="No file selected")
        self.process_button.config(state=tk.DISABLED)
        self.status_label.config(text="")
        self.canvas.delete("all")
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.delete(1.0, tk.END)
        self.text_widget.config(state=tk.DISABLED)

    def process_file(self):
        
        if not self.file_path:
            messagebox.showerror("Error", "Please select a log file first!")
            return

        self.upload_button.config(state=tk.DISABLED)
        self.process_button.config(state=tk.DISABLED)
        self.clear_button.config(state=tk.DISABLED)
        self.clusters_dropdown.config(state=tk.DISABLED)
        self.status_label.config(text="Processing...")
        self.root.update()

        try:
            self.canvas.delete("all")
            self.text_widget.config(state=tk.NORMAL)
            self.text_widget.delete(1.0, tk.END)
            self.text_widget.config(state=tk.DISABLED)

            self.logs = self.load_auth_logs(self.file_path)
            if not self.logs:
                raise ValueError("No valid HTTP logs found in the CSV!")

            self.features = self.preprocess_logs(self.logs)
            self.anomalies, self.clusters = self.custom_kmeans(self.features, n_clusters=self.n_clusters)
            self.private_features = self.add_noise(self.features, epsilon=0.5)
            self.private_anomalies, _ = self.custom_kmeans(self.private_features, n_clusters=self.n_clusters)

            self.display_results()

        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.upload_button.config(state=tk.NORMAL)
            self.process_button.config(state=tk.NORMAL)
            self.clear_button.config(state=tk.NORMAL)
            self.clusters_dropdown.config(state=tk.NORMAL)
            self.status_label.config(text="")

    def load_auth_logs(self, csv_file):
        
        logs = []
        with open(csv_file, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if not row['IP'].startswith('10.') or not row['Time'].startswith('['):
                    continue
                try:
                    time_str = row['Time'].strip('[')
                    timestamp = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S')
                    log = {
                        'ip': row['IP'],
                        'timestamp': timestamp,
                        'url': row['URL'],
                        'status': int(row['Staus'])  
                    }
                    logs.append(log)
                except ValueError:
                    continue
        print(f"Loaded {len(logs)} valid logs")
        return logs

    def preprocess_logs(self, logs):
        
        features = []
        for log in logs:
            hour = log['timestamp'].hour
            day = log['timestamp'].weekday()
            success = 1 if log['status'] in [200, 304] else 0
            features.append([hour, day, success])
        print(f"Preprocessed {len(features)} feature vectors")
        return features

#kmeans algorithm
    def custom_kmeans(self, data, n_clusters, max_iterations=100):
       
        data = np.array(data)
        n_samples = len(data)
        
        
        random_indices = random.sample(range(n_samples), n_clusters)
        centroids = data[random_indices]
        
        for _ in range(max_iterations):
            
            distances = np.array([[np.linalg.norm(point - centroid) for centroid in centroids] 
                                for point in data])
            labels = np.argmin(distances, axis=1)
            
        
            new_centroids = np.array([data[labels == k].mean(axis=0) if len(data[labels == k]) > 0 
                                    else centroids[k] for k in range(n_clusters)])
            
            # Check for convergence
            if np.all(centroids == new_centroids):
                break
            centroids = new_centroids

        
        cluster_counts = {}
        for c in set(labels):
            count = list(labels).count(c)
            cluster_counts[c] = count
        
        anomaly_cluster = min(cluster_counts, key=cluster_counts.get)
        print(f"Smallest cluster (anomaly): Cluster {anomaly_cluster} with {cluster_counts[anomaly_cluster]} points")
        anomalies = [1 if c == anomaly_cluster else 0 for c in labels]
        
        return anomalies, labels

    def laplace_noise(self, scale):
        
        u = random.random() - 0.5
        return -scale * (1 if u >= 0 else -1) * (0.0001 + abs(u))

    def add_noise(self, data, epsilon=0.5):
       
        sensitivity = 1.0
        scale = sensitivity / epsilon
        noisy_data = []
        for point in data:
            noisy_point = [p + self.laplace_noise(scale) for p in point]
            noisy_data.append(noisy_point)
        print(f"Generated {len(noisy_data)} noisy feature vectors")
        return noisy_data

    def reidentification_risk(self, logs):
       
        unique_ips = {}
        for log in logs:
            ip = log['ip']
            unique_ips[ip] = unique_ips.get(ip, 0) + 1
        single_occurrences = sum(1 for count in unique_ips.values() if count == 1)
        risk = single_occurrences / len(logs) if logs else 0.0
        return risk

    def display_results(self):
      
        sample_size = min(1000, len(self.features))
        sampled_indices = random.sample(range(len(self.features)), sample_size)
        for i in sampled_indices:
            feature, anomaly = self.features[i], self.anomalies[i]
            x = feature[1] * 70 + 50
            y = 350 - feature[0] * 14
            color = "red" if anomaly else "blue"
            self.canvas.create_oval(x-3, y-3, x+3, y+3, fill=color)


        self.canvas.create_text(250, 380, text="Day of Week (0-6)", font=("Arial", 10))
        self.canvas.create_text(20, 200, text="Hour of Day (0-23)", font=("Arial", 10), angle=90)

        total_points = len(self.anomalies)
        anomaly_rate = sum(self.anomalies) / total_points if total_points > 0 else 0.0
        private_anomaly_rate = sum(self.private_anomalies) / len(self.private_anomalies) if len(self.private_anomalies) > 0 else 0.0
        risk = self.reidentification_risk(self.logs)
        cluster_counts = {}
        for c in set(self.clusters):
            count = list(self.clusters).count(c)
            cluster_counts[f"Cluster {c}"] = count
        top_clusters = sorted(cluster_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        non_noise_total = sum(count for count in cluster_counts.values())
        cluster_text = f"Total Points in Clusters: {non_noise_total}\n" + "\n".join([f"{k}: {v} points" for k, v in top_clusters])

        analysis_text = (
            f"Anomaly Detection Rate: {anomaly_rate:.2%}\n"
            f"Privacy-Preserving Anomaly Rate: {private_anomaly_rate:.2%}\n"
            f"Re-identification Risk: {risk:.2%}\n"
            f"{cluster_text}"
        )
        print(f"Debug: Analysis Text = {analysis_text}")

        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.delete(1.0, tk.END)
        self.text_widget.insert(tk.END, analysis_text)
        self.text_widget.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = AnomalyDetectionApp(root)
    root.mainloop()