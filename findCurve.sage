
def findCurve(prime, curveCofactor, twistCofactor):
  F = GF(prime)

  for A in xrange(3, int(1e9)):
    if (A-2) % 4 != 0:
      continue

    try:
      E = EllipticCurve(F, [0, A, 0, 1, 0])
    except:
      continue

    groupOrder = E.order()
    twistOrder = 2*(prime+1)-groupOrder

    if (groupOrder % curveCofactor == 0 and
      is_prime(groupOrder // curveCofactor) and
      twistOrder % twistCofactor == 0 and
      is_prime(twistOrder // twistCofactor)):
      return A

def find1Mod4(prime):
  assert((prime % 4) == 1)
  return findCurve(prime, 8, 4)

def find3Mod4(prime):
  assert((prime % 4) == 3)
  return findCurve(prime, 4, 4)

print(find1Mod4(257))
print(find3Mod4(263))
