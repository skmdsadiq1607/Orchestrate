import pandas as pd

dr = pd.read_csv("dataset/deletion_requests.csv")
print(dr[dr['case_id'] == 'case_71'].to_dict('records'))
