#necessary libraries

import os
import cv2
import pickle
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm
from sklearn.preprocessing import OneHotEncoder
from keras.preprocessing.image import ImageDataGenerator


#functions to load the images and corresponding labels

def load_normal(norm_path):
    norm_files = np.array(os.listdir(norm_path))
    norm_labels = np.array([0]*len(norm_files))
    norm_images = []
    
    for image in tqdm(norm_files):
        image = cv2.imread(norm_path + image)
        image = cv2.resize(image, dsize=(224,224))
        image = clahe(image)
        norm_images.append(image)
        
    norm_images = np.array(norm_images)
    
    return norm_images, norm_labels   
     
def load_pneumonia(pneu_path):
    pneu_files = np.array(os.listdir(pneu_path))
    pneu_labels = np.array([1]*len(pneu_files))
    
    pneu_images = []
    for image in tqdm(pneu_files):
        image = cv2.imread(pneu_path + image)
        image = cv2.resize(image, dsize=(224,224))
        image = clahe(image)
        pneu_images.append(image)
        
    pneu_images = np.array(pneu_images)
    
    return pneu_images, pneu_labels


#function for displaying random images from the training set

def display_random_images():
    fig, axes = plt.subplots(ncols=7, nrows=2, figsize=(16, 4))

    indices = np.random.choice(len(X_train), 14)
    counter = 0
    
    for i in range(2):
        for j in range(7):
            axes[i,j].set_title(Y_train[indices[counter]])
            axes[i,j].imshow(X_train[indices[counter]], cmap='gray')
            axes[i,j].get_xaxis().set_visible(False)
            axes[i,j].get_yaxis().set_visible(False)
            counter += 1
    plt.show()
    
def clahe(image):
    clahe = cv2.createCLAHE(clipLimit=1.5, tileGridSize=(8,8))
    image = clahe.apply(image)
    return image
#invoking the predefined functions to load the training data

norm_images, norm_labels = load_normal('chest_xray/train/NORMAL/')
pneu_images, pneu_labels = load_pneumonia('chest_xray/train/PNEUMONIA/')

#norm_images and pneu_images are going to be our X data while the rest is going to be Y data.

X_train = np.append(norm_images, pneu_images, axis=0)
Y_train = np.append(norm_labels,pneu_labels)

X_train = X_train/255

'''
    X_train.shape  :(5216, 224, 224)
    Y_train.shape  :(5216,)
    np.unique(Y_train,return_counts=True) :  (array(['bacteria', 'normal', 'virus'], dtype='<U8'),
                                              array([2530, 1341, 1345], dtype=int64))
'''


#displaying random images from the training set
display_random_images()

#loading the test data
norm_images_test, norm_labels_test = load_normal('chest_xray/test/NORMAL/')
pneu_images_test, pneu_labels_test = load_pneumonia('chest_xray/test/PNEUMONIA/')

X_test = np.append(norm_images_test, pneu_images_test, axis=0)
Y_test = np.append(norm_labels_test, pneu_labels_test)
X_test = X_test/255

#use this to save variables
file =  open('SCANIA_data.pickle', 'wb')
pickle.dump((X_train, X_test, Y_train, Y_test), file)
    
#use this to load variables
file =  open('SCANIA_data.pickle', 'rb')
(X_train, X_test, Y_train, Y_test) = pickle.load(file)


#reshaping the X_data from (5216,224,224) to (5216,224,224,1) --> This is required because cnn expects a color channel to be included as its input.

X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], X_train.shape[2], 1)
X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], X_test.shape[2], 1)

#data augmentation 

datagen = ImageDataGenerator(
        rotation_range = 10,  
        zoom_range = 0.1, 
        width_shift_range = 0.1, 
        height_shift_range = 0.1)

datagen.fit(X_train)
train_gen = datagen.flow(X_train, Y_train, batch_size=32)



