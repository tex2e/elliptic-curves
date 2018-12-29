
def findBasepoint(prime, A):
  F = GF(prime)
  E = EllipticCurve(F, [0, A, 0, 1, 0])
  for uInt in range(1, 1e3):
    u = F(uInt)
    v2 = u^3 + A*u^2 + u
    if not v2.is_square():
      continue
    v = v2.sqrt()
    point = E(u, v)
    pointOrder = point.order()
    if pointOrder > 8 and pointOrder.is_prime():
      return point

print(findBasepoint(257, 11))
