package main

type Checker interface {
	Scan(string)
	CreateReport(string) Report
}
