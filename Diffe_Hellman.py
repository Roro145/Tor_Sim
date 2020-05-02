"""
Variable Constraints: P is prime, g is coprime to p-1
p and g are public, priv keys are decided
"""

"""
conversion using the given keys, works for the first or second step
"""
def diffe_Hellman_step(p_val, g_val, priv_key):
    return (g_val ** priv_key) % p_val

#all 4 of these are prime
p_val = 355933
g_val = 355633
user_1_key = 354317
user_2_key = 356094

"""
user1_dh_local = diffe_Hellman_step(p_val, g_val, user_1_key)
print("User 1 DH local: " + str(user1_dh_local))

user2_dh_local = diffe_Hellman_step(p_val, g_val, user_2_key)
print("User 2 DH Local: " + str(user2_dh_local))




user1_dh_final = diffe_Hellman_step(p_val, user2_dh_local, user_1_key)
print("User 1 DH final: " + str(user1_dh_final))

user2_dh_final = diffe_Hellman_step(p_val, user1_dh_local, user_2_key)
print("User 2 DH final: " + str(user2_dh_final))
"""
