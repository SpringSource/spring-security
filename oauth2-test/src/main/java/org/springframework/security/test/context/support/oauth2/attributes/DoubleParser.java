/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.context.support.oauth2.attributes;

import org.springframework.util.StringUtils;

/**
 * Turns an annotation String value into a Double
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
public class DoubleParser implements AttributeValueParser<Double> {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Double parse(final String value) {
		if (StringUtils.isEmpty(value)) {
			return null;
		}
		return Double.valueOf(value);
	}

}
