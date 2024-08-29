import pandas as pd

df = pd.read_csv("UNSW_NB15_training-set.csv")

# Create and save the frequency count mappings
service_counts = df['service'].value_counts().to_dict()
proto_counts = df['proto'].value_counts().to_dict()
attack_cat_counts = df['attack_cat'].value_counts().to_dict()
state_counts = df['state'].value_counts().to_dict()

pd.Series(service_counts).to_csv('service_counts.csv')
pd.Series(proto_counts).to_csv('proto_counts.csv')
pd.Series(attack_cat_counts).to_csv('attack_cat_counts.csv')
pd.Series(state_counts).to_csv('state_counts.csv')