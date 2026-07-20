'''
Given a binary array nums, return the maximum number of consecutive 1's in the array.

 

Example 1:

Input: nums = [1,1,0,1,1,1]
Output: 3
Explanation: The first two digits or the last three digits are consecutive 1s. The maximum number of consecutive 1s is 3.
Example 2:

Input: nums = [1,0,1,1,0,1]
Output: 2

'''

class Solution:
    def findMaxConsecutiveOnes(self, nums: list[int]) -> int:
        current_streak = 0
        highest_streak = 0

        for i in nums:
            if i == 1:
                current_streak += 1
            else:
                if current_streak > highest_streak:
                    highest_streak = current_streak
                current_streak = 0

        if current_streak > highest_streak:
            highest_streak = current_streak

        return highest_streak

test=[1,1,1,1,1,0,1,1,0,1]


solve = Solution()

print(solve.findMaxConsecutiveOnes(test))


