set table "20120816_-_Differential_-_Windsor.f2.table"; set format "%.5f"
set samples 100; plot [x=-1.5:1.5]  1/sqrt(2*pi*0.112) * exp(- ((x--0.256)**2 / (2*0.112)) ) 
