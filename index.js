//Dependencies
const Axios = require("axios")
const Fs = require("fs")

//Variables
const Self_Args = process.argv.slice(2)

//Main
if(!Self_Args.length){
    console.log("node index.js <domain> <output>")
}

if(!Self_Args[1]){
    console.log("Invalid output.")
    process.exit()
}

console.log("Scanning the domain, please wait.")
void async function Main(){
    var results = ""
    var phase_1 = await Axios({
        method: "GET",
        url: `https://www.threatminer.org/domain.php?q=${Self_Args[0]}&api=True&rt=1`
    })
    var phase_2 = await Axios({
        method: "GET",
        url: `https://www.threatminer.org/domain.php?q=${Self_Args[0]}&api=True&rt=3`
    })
    var phase_3 = await Axios({
        method: "GET",
        url: `https://www.threatminer.org/domain.php?q=${Self_Args[0]}&api=True&rt=6`
    })

    phase_1 = phase_1.data
    phase_2 = phase_2.data
    phase_3 = phase_3.data

    results = "----------------------> Threat miner data <----------------------"
    if(!phase_1.results){
        results += "\nNone."
    }else{
        for( i in phase_1.results ){
            results += `\nDomain:${Self_Args[0]}
Nameservers:${phase_1.results[i].whois.nameservers}
Whois MD5:${phase_1.results[i].whois.whois_md5}

Billing:
Organization:${phase_1.results[i].whois.billing_info.Organization}
City:${phase_1.results[i].whois.billing_info.City}
State:${phase_1.results[i].whois.billing_info.State}
Country:${phase_1.results[i].whois.billing_info.Country}
Postal code:${phase_1.results[i].whois.billing_info.Postal_Code}

Registrant:
Organization:${phase_1.results[i].whois.registrant_info.Organization}
City:${phase_1.results[i].whois.registrant_info.City}
Country:${phase_1.results[i].whois.registrant_info.Country}
State:${phase_1.results[i].whois.registrant_info.State}
Street:${phase_1.results[i].whois.registrant_info.Street}
Postal code:${phase_1.results[i].whois.registrant_info.Postal_Code}

Emails:
Admin: ${phase_1.results[i].whois.emails.admin}
Tech: ${phase_1.results[i].whois.emails.tech}
Registrant: ${phase_1.results[i].whois.emails.registrant}
Billing: ${phase_1.results[i].whois.emails.billing}

Creating date: ${phase_1.results[i].whois.creation_date}`
        }
    }

    results += "\n\n----------------------> Threat miner report <----------------------"
    if(!phase_3.results){
        results += "\nNone."
    }else{
        for( i in phase_3.results ){
            results += `\n\nFile name: ${phase_3.results[i].filename}
URL: ${phase_3.results[i].URL}
Year: ${phase_3.results[i].year}`
        }
    }

    results += "\n\n----------------------> Threat miner others <----------------------"
    if(!phase_2.results){
        results += "\nNone."
    }else{
        for( i in phase_2.results ){
            results += `\n\nDomain: ${phase_2.results[i].domain}
URL: ${phase_2.results[i].uri}`
        }
    }

    console.log(`Saving the results to ${Self_Args[1]}`)
    Fs.writeFileSync(Self_Args[1], results, "utf8")
    console.log(`Results successfully saved to ${Self_Args[1]}`)
}()