[
    {
        '$match': {
            'cve.references.reference_data.url': {
                '$regex': re.compile(r"^.*github.*commit.*([0-9a-f]{40}).*$")
            }
        }
    }, {
        '$project': {
            'cve_id': '$cve.CVE_data_meta.ID',
            'urls': {
                '$map': {
                    'input': {
                        '$filter': {
                            'input': '$cve.references.reference_data.url',
                            'as': 'url',
                            'cond': {
                                '$regexMatch': {
                                    'input': '$$url',
                                    'regex': re.compile(r"^.*github.*commit.*([0-9a-f]{40}).*$")
                                }
                            }
                        }
                    },
                    'as': 'url',
                    'in': {
                        '$regexFind': {
                            'input': '$$url',
                            'regex': re.compile(r"^.*github.com\/(.*)\/commit\/.*([0-9a-f]{40}).*$")
                        }
                    }
                }
            }
        }
    }, {
        '$project': {
            'cve_id': 'cve_id',
            'patches': '$urls.captures'
        }
    }
]
