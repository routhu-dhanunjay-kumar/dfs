
## ![image](https://user-images.githubusercontent.com/108211929/233038413-d125fd46-e345-4eb6-9f4b-e5063fd41d6a.png) OPEN POLICY AGENT

OPA is an open source, general-purpose policy engine that enables unified, context-aware policy enforcement across the entire stack. The project was accepted into the CNCF sandbox in April 2018 and one year later was promoted to incubation. 


# Table Of Content

1. [ Installation. ](#install)
2. [ Usage. ](#work)
3. [ How OPA is Working. ](#working)

    [Taking Input](#input)

    [Executing Policies](#policies)

    [Handling Error](#errorH)
1. [Want to learn more. ](#learn)

<a name="install"></a>
## 1. Installation

commands to install opa

<a name="work"></a>
## 2. Usage
    OPA gives you a high-level declarative language to author and enforce policies across your stack like 

    What tags must be set on resource R before it's created?
    Is cloud watch and log metrics enabled ?
    Is alarm name set for resources ?


<a name="working"></a>
## 3. How OPA is Working 

<a name="input"></a>
### 3.1 Taking Input

    It is taking input from tfplan.json which is created by terraform modules at plan stage.
    Input created by terraform code is in form of JSON object which is passed to OPA as data.
    
    terraform show -json tfplan.binary > tfplan.json

<a name="policies"></a>
### 3.2 Executing Policies

    Policies are written in rego file which executes on the input data.
    Policies  validate whether the plan data which will be applied to create resources are valid or not.
    If plan data is valid, OPA will return true and execution of next stage of pipeline will continue.
    If Plan data is invalid, OPA will return false and pipeline execution will stop and error message is thrown.
    
    allow{
        function_name
    }

    deny{
        not function_name
    }

<a name="errorH"></a>
### 3.3 Handling Error

    If OPA fails then error message is thrown to service now that OPA policies have been failed.
    Exactly what policy has failed is present in policy output.json like for what tags,resources or alarm name OPA has failed.
    
    data.terraform.aws.${resources[j].resource_type}' >> policy_output.json


<a name="learn"></a>
## 4. Want to learn more ?

Go to  [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/ "opa document") to get started with documentation and tutorials.

Try OPA with the [Rego Playground](https://play.openpolicyagent.org/ "Rego Playground") to experiment with policies and share your work.

