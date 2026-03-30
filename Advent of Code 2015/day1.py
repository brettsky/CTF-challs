'''
Santa is trying to deliver presents in a large apartment building, but he can't find the right floor - the directions he got are a little confusing. He starts on the ground floor (floor 0) and then follows the instructions one character at a time.

An opening parenthesis, (, means he should go up one floor, and a closing parenthesis, ), means he should go down one floor.

The apartment building is very tall, and the basement is very deep; he will never find the top or bottom floors.

For example:

(()) and ()() both result in floor 0.
((( and (()(()( both result in floor 3.
))((((( also results in floor 3.
()) and ))( both result in floor -1 (the first basement level).
))) and )())()) both result in floor -3.
To what floor do the instructions take Santa?
'''


directions = 'day1_input.txt'
current_floor = 0
counter = 0
try:
    with open(directions, 'r', encoding='utf-8') as f:
         for line in f:
            for char in line:
                if char == "(":
                     current_floor += 1
                     counter+=1
                     print(f'this is the up floor value{current_floor}')
                elif char == ")":
                    current_floor -=1
                    counter+=1
                    print(f'This is the down floor value {current_floor}')
                if current_floor < 0: 
                    print(current_floor)
                    print(counter)
                    break
            break
         


         print(f'Final Floor {current_floor}')
except FileNotFoundError:
    print(f"Error {directions} is not found")