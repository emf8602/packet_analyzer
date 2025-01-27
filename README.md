# packet_analyzer
In this assignment you will write a network packet analyzer called pktsniffer that reads packets and produces a detailed summary of those packets. The pktsniffer program first reads packets from a specified file (pcap file). Then it extracts and displays the different headers of the captured packets.


# Pep 8 Guidelines
This section is here to ensure I stay on top of keeping my code in Pep 8 style  
https://peps.python.org/pep-0008/   

**Indentation**- 4 spaces per indentation level and don't use tabs

**Line Length**- Max of 79 characters

**Binary Operator Line Breaks**- 
```python
income = (gross_wages
          + taxable_interest
          + (dividends - qualified_dividends)
          - ira_deduction
          - student_loan_interest)
```

**Blank Lines**-  
Surround top level functions with two blank lines  
Surround mathods within a class with a single blank line

**Imports**-
Should be on seperate lines and grouped by
<li>Standard library imports.  
<li>Related third party imports.  
<li>Local application/library specific imports  

**Whitespace in Expressions**-  
No trailing whitespace  
`spam(ham[1], {eggs: 2})`  
`if x == 4: print(x, y); x, y = y, x`  
`def complex(real, imag=0.0):
    return magic(r=real, i=imag)`  

**Comments**- Complete sentences  

**Doc Strings**-  
Write docstrings for all public modules, functions, classes, and methods. Docstrings are not necessary for non-public methods, but you should have a comment that describes what the method does. This comment should appear after the def line.
```python
"""Return a foobang

Optional plotz says to frobnicate the bizbaz first.
"""

"""Return an ex-parrot."""
```

**Naming Convention**- lower_case_with_underscores

**Programming Recomendations**-  
Don't use `a+=b` or `a = a+b` for string concatination. use `''.join()`  
Use `is` and `is not` when comparing to `None`  
Either all return statements in a function should return an expression, or none of them should  
Object type comparisons should always use `isinstance()` instead of comparing types directly