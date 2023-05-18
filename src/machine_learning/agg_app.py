import os
import re
import time
import math

import joblib

import pandas as pd
import numpy as np

import seaborn as sns
import matplotlib.pyplot as plt
# %matplotlib inline 

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
from sklearn.metrics import classification_report, confusion_matrix, precision_score, roc_auc_score, accuracy_score 


from imblearn.over_sampling import SMOTE

plt.style.use("ggplot")

###
### Global Variables
###

dataset_directory = "data"

legitimate_traffics = "agg_legitimate.csv"
ddos_traffics = "agg_attacks.csv"

data = None
model_scores = dict()
base_model_scores = dict()

dependent = "traffic_type"

agg_label = "AGG"

accuracy_label = "Accuracy"
auc_label = "AUC"
precision_label = "Precision"

# scaler = MinMaxScaler()
scaler = StandardScaler()
oversampling = SMOTE()

save_model_directory = "build"
agg_model_directory = "agg_model"


terminal_width = os.get_terminal_size().columns

###
### Helper Functions
###

def to_percentage(number):
    number = number * 100
    factor = 10 ** 2
    return math.floor(number * factor) / factor


def to_percentage(number):
    number = number * 100
    factor = 10 ** 2
    return math.floor(number * factor) / factor


def get_model_directory(model_name):
    model_dir = os.path.join(os.getcwd(), save_model_directory)
    return os.path.join(model_dir, model_name)

def draw_line_on_terminal(line_length):
    line = ""
    symbol = "="
    for i in range(line_length):
        line += symbol
    return line

def add_header_section(header, line_size=None):
    if line_size == None:
        line_size = terminal_width

    print("\n")
    print(header)
    print(draw_line_on_terminal(line_size))
    print("\n")


def build_machine_learning_models():
    ###
    ### initialize the dataframe variable to None
    ###
    df = None
    legitimate = None
    attacks = None

    ###
    ### Load dataset
    ###
    
    add_header_section("Loading dataset files ...")
    try:
        file_path_1 = os.path.join(os.getcwd(), dataset_directory, legitimate_traffics)
        file_path_2 = os.path.join(os.getcwd(), dataset_directory, ddos_traffics)
        legitimate = pd.read_csv(file_path_1)
        attacks = pd.read_csv(file_path_2)

        df = pd.concat([legitimate, attacks], ignore_index=True)

        if not isinstance(df, pd.DataFrame):
            msg = "Default Message"
            if not isinstance(df, pd.DataFrame):
                msg = "Poorly formed pandas dataframe"

            print("\n")
            print(df.shape)
            raise Exception(msg)
        else:
            print("Done!!!")  
            print("\n\n")
    except Exception as ex:
        print(ex.args)
        exit()
    
    ###
    ###
    ###
    add_header_section("View first five record in the loaded dataframe ...")
    print(df.head())  
    print("\n\n")

    ###
    ###
    ###
    add_header_section("View all columns, their respective datatypes and record count ...")
    print(df.info())
    print("\n\n")

    ###
    ###
    ###
    add_header_section("View class distribution of traffic type (DDoS or Legitimate) using a Pie Chart")
    class_label = ["Legitimate Traffics", "DDoS Traffics"]
    dependent_variable = [df[dependent].value_counts()[0], df[dependent].value_counts()[1]]
    fig = plt.figure(figsize=(5, 4), dpi=144, tight_layout=False)
    plt.pie(dependent_variable, labels=class_label, autopct='%1.1f%%')
    plt.title("\n\nLegitimate Traffics to DDoS Traffics Ratio")
    plt.show()
    print("\n\n")

    ###
    ###
    ###
    add_header_section("Pre-processing dataset from modelling ...")
    print("\n\tRemove missing data or record from the dataset ...")
    df.dropna(inplace=True)
    df = df.replace([np.inf, -np.inf], np.nan)
    df.dropna(inplace=True)
    print("\n\tDone!!!\n\n")

    print("\n\tConvert dependent variable into categorical variable from the dataset ...")
    df[dependent] = df[dependent].astype("category")
    print("\n\tDone!!!\n\n")
    
    print("\n\tCreating the dependent and independent variable groups from the dataset ...")
    y = df[dependent]
    X = scaler.fit_transform(df.drop([dependent], axis=1))
    print("\n\tDone!!!\n\n")

    print("\n\tRemoving the imbalance in the dataset using SMOTE algorithm ...")
    X, y = oversampling.fit_resample(X, y)
    print("\n\tDone!!!\n\n")

    print("\n\tSplitting the dataset into training and testing dataset in the ratio of 70 to 30 respectively ...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.3, random_state = 0)
    print("\tTRAINING DATASET SHAPE ")
    print("\tTrain X: ", X_train.shape)
    print("\tTrain y: ", y_train.shape)
    print("\n\tTESTING DATASET SHAPE ")
    print("\tTest X: ", X_test.shape)
    print("\tTest y: ", y_test.shape)
    print("\n\tDone!!!\n\n")


    add_header_section("SVM Model Analysis (Building Base and Hyper-Tuned Models)...")
    print("\n\tBase SVM Model Analysis ...")
    print("\n\tFitting Base SVM Model ...")
    SVM_model = svm.SVC(kernel='linear', C=0.025, random_state=0)
    SVM_model.fit(X_train, y_train)
    print("\n\tDone!!!\n\n")


    print('\n\tSVM MODEL SUMMARY REPORT')
    print('\t=======================================================================')
    print('\t=======================================================================\n\n')

    print('\tTraining Accuracy :', SVM_model.score(X_train, y_train))
    print('\tTesting Accuracy :', SVM_model.score(X_test, y_test))
    y_pred = SVM_model.predict(X_test)
    confusion_mat = confusion_matrix(y_test, y_pred)
                
    print('\n\tCLASSIFICATION REPORT\n')
    print(classification_report(y_pred, y_test, target_names =['DDoS','Legitimate']))

    print('\nCONFUSION MATRIX')
    plt.figure(figsize= (6,4))
    ax = sns.heatmap(confusion_mat, annot = True, cmap="Blues")
    ax.set_title('Seaborn Confusion Matrix with labels\n\n')
    ax.set_xlabel('\nPredicted Values')
    ax.set_ylabel('Actual Values ')
    ax.xaxis.set_ticklabels(['Legitimate','DDoS'])
    ax.yaxis.set_ticklabels(['Legitimate','DDoS'])
    plt.show()

    print("\n\n\tMODEL EVALUATION SCORES\n")
    base_model_scores[agg_label] = dict()
    base_model_scores[agg_label][accuracy_label] = to_percentage(accuracy_score(y_test, y_pred))
    base_model_scores[agg_label][auc_label] = to_percentage(roc_auc_score(y_test, y_pred))
    base_model_scores[agg_label][precision_label] = to_percentage(precision_score(y_test, y_pred))

    print("\tAccuracy Score: " + str(base_model_scores[agg_label][accuracy_label]))
    print("\tAUC Score: " + str(base_model_scores[agg_label][auc_label]))
    print("\tPrecision Score: " + str(base_model_scores[agg_label][precision_label]))
    print("\n\tDone!!!\n\n")
    print("\n\n")

    print("\n\n\tSAVING SVM MODEL TO FILE\n")
    save_dir = get_model_directory(agg_model_directory)
    model_path = os.path.join(save_dir, "model")
    with open(model_path, "wb") as file:
        joblib.dump(SVM_model, file)
    print("\n\tDone!!!\n\n")
    print("\n\n")

    add_header_section("Models Built Successfully ....")
    print("\n\n")

build_machine_learning_models()
