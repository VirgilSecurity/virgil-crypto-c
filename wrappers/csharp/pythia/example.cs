using System;
using System.Runtime.InteropServices;

public class Example
{
    [DllImport("example", EntryPoint = "print")]
    public static extern void Print(string message);

    [DllImport("example", EntryPoint = "addition")]
    public static extern long Addition(long a, long b);
}
